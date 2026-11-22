//go:build linux

package platform

import (
	"errors"
	"net"
	"os"
	"testing"
)

func TestLinuxLiveIdentitySocketAndFD(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	process, err := ReadProcessAt(DefaultProcRoot, os.Getpid())
	if err != nil || process.StartTicks <= 0 {
		t.Fatalf("identity=%+v error=%v", process, err)
	}
	count, err := CountOpenFDsFor(process)
	if err != nil || count < 1 {
		t.Fatalf("FD count=%d error=%v", count, err)
	}
	wrong := process
	wrong.StartTicks++
	if _, err := CountOpenFDsFor(wrong); err == nil {
		t.Fatal("FD count accepted stale identity")
	}
	rows, err := Connections()
	if err != nil {
		t.Fatal(err)
	}
	owners, err := SocketOwners(DefaultProcRoot)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	for _, row := range rows {
		if row.LocalPort == port && row.State == "LISTEN" {
			owner := owners[row.Inode]
			if owner.PID != process.PID || owner.StartTicks != process.StartTicks {
				t.Fatalf("listener owner=%+v expected=%+v", owner, process)
			}
			return
		}
	}
	t.Fatal("live listener absent from TCP table")
}
func TestLinuxLiveCgroupAndPressure(t *testing.T) {
	group, err := SelfCgroup()
	if err != nil {
		t.Fatalf("live cgroup: %v", err)
	}
	if group.PID != os.Getpid() || group.Path == "" || group.StartTicks <= 0 {
		t.Fatalf("cgroup=%+v", group)
	}
	for _, resource := range []Resource{PressureCPU, PressureMemory, PressureIO} {
		pressure, err := ReadPressure(resource)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				t.Logf("PSI unavailable: %v", err)
				continue
			}
			t.Fatal(err)
		}
		if !pressure.HasSome {
			t.Errorf("resource %s missing some", resource)
		}
	}
}
