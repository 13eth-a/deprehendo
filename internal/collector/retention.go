package collector

import (
	"strings"
	"unsafe"

	"deprehendo/internal/platform"
)

func cloneSnapshot(s Snapshot) Snapshot {
	if s.System != nil {
		v := *s.System
		v.DiskFilesystem = strings.Clone(v.DiskFilesystem)
		s.System = &v
	}
	if s.Cgroup != nil {
		s.Cgroup = cloneCgroup(s.Cgroup)
	}
	if s.Pressure != nil {
		m := make(map[platform.Resource]platform.PressureSnapshot, len(s.Pressure))
		for k, v := range s.Pressure {
			m[platform.Resource(strings.Clone(string(k)))] = v
		}
		s.Pressure = m
	}
	s.Processes = append([]ProcessSnapshot(nil), s.Processes...)
	for i := range s.Processes {
		p := &s.Processes[i]
		p.Name = strings.Clone(p.Name)
		p.State = strings.Clone(p.State)
		if p.Cgroup != nil {
			p.Cgroup = cloneCgroup(p.Cgroup)
		}
	}
	s.Connections = append([]ConnectionSnapshot(nil), s.Connections...)
	for i := range s.Connections {
		c := &s.Connections[i]
		c.LocalAddr = strings.Clone(c.LocalAddr)
		c.RemoteAddr = strings.Clone(c.RemoteAddr)
		c.State = strings.Clone(c.State)
	}
	s.Metrics = append([]CollectorTiming(nil), s.Metrics...)
	for i := range s.Metrics {
		s.Metrics[i].Name = strings.Clone(s.Metrics[i].Name)
	}
	s.Errors = append([]CollectionError(nil), s.Errors...)
	for i := range s.Errors {
		s.Errors[i].Collector = strings.Clone(s.Errors[i].Collector)
		s.Errors[i].Err = strings.Clone(s.Errors[i].Err)
	}
	return s
}

func cloneCgroup(source *platform.CgroupSnapshot) *platform.CgroupSnapshot {
	v := *source
	v.Path = strings.Clone(v.Path)
	v.CPUMax = strings.Clone(v.CPUMax)
	return &v
}

// snapshotPayloadBytes conservatively estimates detached go payload retained
// outside fixed ring slots. allocation rounding and map bookkeeping have
// explicit allowances. this is a payload budget, not an RSS/Go heap limit:
// transient collection, query copies and the runtime are additional memory.
func snapshotPayloadBytes(s Snapshot) int64 {
	var n int64
	text := func(v string) {
		if len(v) > 0 {
			n += int64(len(v)) + 32
		}
	}
	cg := func(v *platform.CgroupSnapshot) {
		if v == nil {
			return
		}
		n += int64(unsafe.Sizeof(*v)) + 32
		text(v.Path)
		text(v.CPUMax)
	}
	if s.System != nil {
		n += int64(unsafe.Sizeof(*s.System)) + 32
		text(s.System.DiskFilesystem)
	}
	cg(s.Cgroup)
	if s.Pressure != nil {
		n += 128
		for k := range s.Pressure {
			n += int64(unsafe.Sizeof(platform.PressureSnapshot{})) + 128
			text(string(k))
		}
	}
	n += int64(cap(s.Processes)) * int64(unsafe.Sizeof(ProcessSnapshot{}))
	for _, p := range s.Processes {
		text(p.Name)
		text(p.State)
		cg(p.Cgroup)
	}
	n += int64(cap(s.Connections)) * int64(unsafe.Sizeof(ConnectionSnapshot{}))
	for _, c := range s.Connections {
		text(c.LocalAddr)
		text(c.RemoteAddr)
		text(c.State)
	}
	n += int64(cap(s.Metrics)) * int64(unsafe.Sizeof(CollectorTiming{}))
	for _, m := range s.Metrics {
		text(m.Name)
	}
	n += int64(cap(s.Errors)) * int64(unsafe.Sizeof(CollectionError{}))
	for _, e := range s.Errors {
		text(e.Collector)
		text(e.Err)
	}
	return n
}
