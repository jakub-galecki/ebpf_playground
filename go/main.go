package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"C"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)
import "unsafe"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux  -type command bpf tracepoint.c -- -I../headers

func toBytes(raw [256]int8) []byte {
	dd := C.GoBytes((unsafe.Pointer)(&raw[0]), 256)
	return dd
}

func toStr(raw [256]int8) string {
	dd := C.GoString((*C.char)(&raw[0]))
	return dd
}

func main() {
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

	if err = objs.TargetPids.Update(uint32(31818), uint8(1), ebpf.UpdateAny); err != nil {
		panic(err)
	}

	rb, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		panic(err)
	}

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
		command := toBytes(e.Buf)
		log.Printf("ts: %d, comm: %s", e.Ts, command)
	}
}
