package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"deprehendo/internal/incident"
)

// runInspect validates a bundle completely before printing any details.
func runInspect(args []string, stdout, stderr io.Writer) int {
	path, flags := splitInspectArgs(args)
	fs := flag.NewFlagSet("deprehendo-agent inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeline := fs.Bool("timeline", false, "print the event timeline")
	privacy := fs.Bool("privacy", false, "print data-category presence report")
	snapshot := fs.String("snapshot", "", "print a zero-based snapshot index")
	at := fs.String("at", "", "print snapshot nearest relative duration (e.g. -10s) or RFC3339 time")
	if err := fs.Parse(flags); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "deprehendo-agent: inspect requires exactly one .deprehendo bundle")
		return 2
	}
	if *snapshot != "" && *at != "" {
		fmt.Fprintln(stderr, "deprehendo-agent: choose only one of --snapshot and --at")
		return 2
	}
	bundle, err := incident.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: inspect: %v\n", err)
		return 1
	}
	if *snapshot != "" || *at != "" {
		return writeSnapshotInspection(stdout, stderr, bundle, *snapshot, *at)
	}
	writeIncidentSummary(stdout, bundle)
	if *privacy {
		writePrivacyReport(stdout, bundle.Incident.Privacy)
	}
	if *timeline {
		writeIncidentTimeline(stdout, bundle)
	}
	return 0
}

// splitInspectArgs accepts flags on either side of the bundle path.
func splitInspectArgs(args []string) (string, []string) {
	var path string
	flags := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--at" || arg == "--snapshot" {
			flags = append(flags, arg)
			if index+1 < len(args) {
				index++
				flags = append(flags, args[index])
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") && path == "" {
			path = arg
			continue
		}
		flags = append(flags, arg)
	}
	return path, flags
}

func writeIncidentSummary(w io.Writer, bundle *incident.Bundle) {
	i := bundle.Incident
	trigger := i.Trigger.Type
	if i.Trigger.PID > 0 {
		trigger = fmt.Sprintf("%s (pid %d)", trigger, i.Trigger.PID)
	}
	fmt.Fprintln(w, "INCIDENT")
	line(w, "ID", i.ID)
	line(w, "Triggered", i.TriggeredAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	line(w, "Duration", fmt.Sprintf("%ds", int64(i.CaptureEnd.Sub(i.CaptureStart).Seconds())))
	line(w, "Trigger", trigger)
	if i.Trigger.Note != "" {
		line(w, "Note", i.Trigger.Note)
	}
	truncated := "no"
	if i.Truncated {
		truncated = "yes"
	}
	line(w, "Truncated", truncated)
	fmt.Fprintln(w, "\nHOST")
	line(w, "OS", i.Metadata.Host.OS)
	line(w, "Architecture", i.Metadata.Host.Architecture)
	line(w, "CPUs", fmt.Sprintf("%d", i.Metadata.Host.CPUCount))
	memory := "unknown"
	if i.Metadata.Host.MemoryTotal > 0 {
		memory = humanBytes(i.Metadata.Host.MemoryTotal)
	}
	line(w, "Memory", memory)
	collectorerrors := 0
	for _, snapshot := range i.Snapshots {
		collectorerrors += len(snapshot.Errors)
	}
	fmt.Fprintln(w, "\nCAPTURE")
	line(w, "Snapshots", fmt.Sprintf("%d", len(i.Snapshots)))
	line(w, "Events", fmt.Sprintf("%d", len(i.Events)))
	line(w, "Collector Errors", fmt.Sprintf("%d", collectorerrors))
	line(w, "Integrity", "OK")
}

func writePrivacyReport(w io.Writer, report incident.PrivacyReport) {
	fmt.Fprintln(w, "\nPRIVACY")
	line(w, "Hostname", yesNo(report.Hostname))
	line(w, "Command lines", yesNo(report.CommandLines))
	line(w, "Environment variables", yesNo(report.Environment))
	line(w, "Repository name", yesNo(report.RepositoryName))
	line(w, "Network addresses", yesNo(report.NetworkAddresses))
	line(w, "Filesystem paths", yesNo(report.FilesystemPaths))
	line(w, "Process names", yesNo(report.ProcessNames))
	line(w, "User note", yesNo(report.UserNote))
	line(w, "Policy", report.Policy)
}
func yesNo(value bool) string {
	if value {
		return "YES"
	}
	return "NO"
}

func writeSnapshotInspection(stdout, stderr io.Writer, bundle *incident.Bundle, snapshotIndex, atValue string) int {
	i := bundle.Incident
	if len(i.Snapshots) == 0 {
		fmt.Fprintln(stderr, "deprehendo-agent: incident contains no snapshots")
		return 1
	}
	index := -1
	if snapshotIndex != "" {
		var err error
		index, err = parseSnapshotIndex(snapshotIndex, len(i.Snapshots))
		if err != nil {
			fmt.Fprintln(stderr, "deprehendo-agent: inspect:", err)
			return 2
		}
	} else {
		at, err := parseAt(atValue, i.TriggeredAt)
		if err != nil {
			fmt.Fprintln(stderr, "deprehendo-agent: inspect:", err)
			return 2
		}
		index = sort.Search(len(i.Snapshots), func(n int) bool { return !i.Snapshots[n].Timestamp.Before(at) })
		if index == len(i.Snapshots) {
			index--
		} else if index > 0 && at.Sub(i.Snapshots[index-1].Timestamp) <= i.Snapshots[index].Timestamp.Sub(at) {
			index--
		}
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Index    int           `json:"index"`
		Offset   time.Duration `json:"offset_from_trigger"`
		Snapshot any           `json:"snapshot"`
	}{index, i.Snapshots[index].Timestamp.Sub(i.TriggeredAt), i.Snapshots[index]}); err != nil {
		fmt.Fprintln(stderr, "deprehendo-agent: inspect:", err)
		return 1
	}
	return 0
}

func parseSnapshotIndex(value string, count int) (int, error) {
	index, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid snapshot index %q", value)
	}
	if index < 0 || index >= count {
		return 0, fmt.Errorf("snapshot index %d out of range (0..%d)", index, count-1)
	}
	return index, nil
}
func parseAt(value string, triggered time.Time) (time.Time, error) {
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		d, err := time.ParseDuration(value)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid --at duration %q", value)
		}
		return triggered.Add(d), nil
	}
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("--at must be a duration relative to trigger or RFC3339 timestamp")
	}
	return at, nil
}

func writeIncidentTimeline(w io.Writer, bundle *incident.Bundle) {
	i := bundle.Incident
	fmt.Fprintln(w, "\nTIMELINE (UTC)")
	for _, event := range i.Events {
		detail := timelineDetail(event, i.Trigger.Type)
		prefix := event.Timestamp.UTC().Format("15:04:05") + "  " + fmt.Sprintf("%-22s", event.Type)
		if detail == "" {
			fmt.Fprintln(w, strings.TrimRight(prefix, " "))
			continue
		}
		fmt.Fprintln(w, prefix+" "+detail)
	}
}

func timelineDetail(event incident.Event, trigger string) string {
	switch event.Type {
	case incident.ProcessStarted, incident.ProcessExited:
		return fmt.Sprintf("PID %d", event.PID)
	case incident.ProcessStateChanged:
		return fmt.Sprintf("PID %d %s -> %s", event.PID, event.From, event.To)
	case incident.ConnectionOpened, incident.ConnectionClosed:
		if event.Connection != nil {
			c := event.Connection
			return fmt.Sprintf("PID %d %s:%d -> %s:%d", event.PID, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
		}
		return fmt.Sprintf("PID %d", event.PID)
	case incident.CollectorError:
		return "collector " + event.Collector
	case incident.IncidentTriggered:
		return trigger
	case incident.MemoryThreshold:
		return "memory threshold crossed"
	case incident.DiskThreshold:
		return "free disk threshold crossed"
	}
	return ""
}
func line(w io.Writer, label, value string) { fmt.Fprintf(w, "%-20s %s\n", label, value) }
func humanBytes(value uint64) string {
	switch {
	case value >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(value)/(1<<30))
	case value >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(value)/(1<<20))
	case value >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(value)/(1<<10))
	default:
		return fmt.Sprintf("%d B", value)
	}
}
