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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux  -type output_event bpf tracepoint.c -- -I../headers

type parsedEvent struct {
	*bpfOutputEvent

	op      string
	status  bool
	latency uint64
	size    int // always 256 - to fix
	err     string
}

func parseEvent(e bpfOutputEvent) (*parsedEvent, bool) {
	pe := &parsedEvent{
		bpfOutputEvent: &e,
	}

	payload := C.GoBytes((unsafe.Pointer)(&e.Buf[0]), 256)
	status := C.GoBytes((unsafe.Pointer)(&e.Status[0]), 64)

	pe.op = getOp(string(payload))
	if pe.op == "" {
		return pe, false
	}
	pe.size = len(payload)
	pe.status = getStatus(string(status))
	if !pe.status {
		pe.err = string(status)
	}
	pe.latency = e.Latency
	return pe, true
}

func getStatus(status string) bool {
	if strings.Contains(status, "OK") {
		return true
	}
	return false
}

func getOp(str string) string {
	if strings.Contains(str, "SET") {
		return "SET"
	}
	if strings.Contains(str, "GET") {
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

	writeEnter, err := link.Tracepoint("syscalls", "sys_enter_write", objs.EnterWrite, nil)
	if err != nil {
		panic(err)
	}
	defer writeEnter.Close()

	writeExit, err := link.Tracepoint("syscalls", "sys_exit_write", objs.ExitWrite, nil)
	if err != nil {
		panic(err)
	}
	defer writeExit.Close()

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

	var e bpfOutputEvent
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

		parsed, ok := parseEvent(e)
		if !ok {
			continue
		}
		log.Printf("op: %s, status: %v,  latency: %d, err: %s", parsed.op, parsed.status, parsed.latency, parsed.err)
		// using time.Now here leaves us with some delay, but should be somehow accurate.
		err = wapi.WritePoint(context.Background(),
			influxdb2.NewPointWithMeasurement("database").
				AddTag("type", "dice").
				AddField("operation", parsed.op).
				AddField("status", parsed.status).
				AddField("latency", parsed.latency).
				SetTime(time.Now()))
		if err != nil {
			log.Printf("writing point: %s", err)
		}
	}
}
