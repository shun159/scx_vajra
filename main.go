package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -no-global-types -target amd64 bpf bpf/main.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

func sigHandler() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}

func main() {
	log.Info("running scx_arcus")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Configure CPU topology
	configureCPUTopology(&objs)

	log.Info("Press Ctrl+C to stop...")
	sigHandler()
	log.Info("Shutting down arcus")

}
