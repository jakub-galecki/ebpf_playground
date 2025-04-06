package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"C"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/joho/godotenv"
)

import "unsafe"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux  -type command bpf tracepoint.c -- -I../headers

func toBytes(raw [256]int8) []byte {
	dd := C.GoBytes((unsafe.Pointer)(&raw[0]), 256)
	return dd
}

func toStr(raw [256]int8) string {
	dd := C.GoString((*C.char)(unsafe.Pointer(&raw[0])))
	return dd
}

type parsedComm struct {
	*bpfCommand

	str string
}

func (c *parsedComm) getOp() string {
	if strings.Contains(c.str, "SET") {
		return "SET"
	}
	if strings.Contains(c.str, "GET") {
		return "GET"
	}
	return ""
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.EnterRead, nil)
	if err != nil {
		panic(err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.ExitRead, nil)
	if err != nil {
		panic(err)
	}
	defer tpExit.Close()

	if err = objs.TargetPids.Update(uint32(22762), uint8(1), ebpf.UpdateAny); err != nil {
		panic(err)
	}

	rb, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		panic(err)
	}

	var (
		influxUrl   = os.Getenv("INFLUX_URL")
		influxToken = os.Getenv("INFLUX_TOKEN")
		influxOrg   = os.Getenv("INFLUX_ORG")
	)

	log.Println("InfluxDB URL:", influxUrl)

	client := influxdb2.NewClient(influxUrl, influxToken)
	defer client.Close()
	wapi := client.WriteAPIBlocking(influxOrg, "getting-started")

	go func() {
		<-stopper

		if err := rb.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	var e bpfCommand
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		command := strings.TrimSpace(toStr(e.Buf))
		if command == "" {
			continue
		}
		parsed := &parsedComm{
			bpfCommand: &e,
			str:        command,
		}
		log.Printf("comm: %s", command)
		// using time.Now here leaves us with some delay, but should be somehow accurate.
		err = wapi.WritePoint(context.Background(),
			influxdb2.NewPointWithMeasurement("database").AddTag("type", "dice").AddField("operation", parsed.getOp()).SetTime(time.Now()))
		if err != nil {
			log.Printf("writing point: %s", err)
		}
	}
}
