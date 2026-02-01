package main

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	scx_utils "github.com/shun159/scx_go_utils"
)

type DomainArg struct {
	CacheLevel   int32
	CpuID        int32
	SiblingCpuID int32
	_            int32
}

// enableSiblingCpu enables sibling CPU mapping.
func enableSiblingCpu(objs *bpfObjects, cacheLvl, cpuID, sibID int) error {
	buf := new(bytes.Buffer)
	arg := DomainArg{
		CacheLevel:   int32(cacheLvl),
		CpuID:        int32(cpuID),
		SiblingCpuID: int32(sibID),
	}
	if err := binary.Write(buf, binary.LittleEndian, arg); err != nil {
		return errors.Wrap(err, "Failed to encode DomainArg")
	}

	opts := &ebpf.RunOptions{
		Context: buf.Bytes(),
	}
	_, err := objs.EnableSiblingCpu.Run(opts)
	if err != nil {
		return errors.Wrap(err, "Failed to run enable_sibling_cpu")
	}

	log.Infof("Enabled sibling CPU: CacheLevel=%d, CpuID=%d, SiblingCpuID=%d", cacheLvl, cpuID, sibID)
	return nil
}

// configureCPUTopology configures CPU sibling relationships.
func configureCPUTopology(objs *bpfObjects) {
	topology, err := scx_utils.NewTopology()
	if err != nil {
		log.Fatalf("Failed to read CPU topology: %s", err)
	}

	log.Infof("Configuring CPU topology for %d CPUs...", len(topology.AllCPUs))

	for _, cpu := range topology.AllCPUs {
		for _, sibID := range cpu.SiblingIDs {
			if cpu.ID == sibID {
				continue
			}
			if err := enableSiblingCpu(objs, 0, cpu.ID, sibID); err != nil {
				log.Errorf("Failed to enable SMT sibling (cpu%d-cpu%d): %s", cpu.ID, sibID, err)
			}
		}

		for _, sib := range topology.AllCPUs {
			if cpu.ID == sib.ID {
				continue
			}

			if cpu.L2ID != -1 && cpu.L2ID == sib.L2ID {
				if err := enableSiblingCpu(objs, 2, cpu.ID, sib.ID); err != nil {
					log.Errorf("Failed to enable L2 sibling: %s", err)
				}
			}

			if cpu.L3ID != -1 && cpu.L3ID == sib.L3ID {
				if err := enableSiblingCpu(objs, 3, cpu.ID, sib.ID); err != nil {
					log.Errorf("Failed to enable L3 sibling: %s", err)
				}
			}
		}
	}
	log.Info("CPU topology configuration completed.")
}
