module github.com/shun159/scx_vajra

go 1.25.6

require (
	github.com/cilium/ebpf v0.20.0
	github.com/pkg/errors v0.9.1
	github.com/shun159/scx_go_utils v0.0.0-20241228162204-517462828ab9
	github.com/sirupsen/logrus v1.9.4
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
