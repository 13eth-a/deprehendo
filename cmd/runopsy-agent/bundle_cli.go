package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"runopsy/internal/incident"
)

func runIncidents(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(stderr, "runopsy-agent: incidents requires the list subcommand")
		return 2
	}
	fs := flag.NewFlagSet("runopsy-agent incidents list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	directory := fs.String("incident-dir", defaultIncidentDir(), "incident bundle directory")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *directory == "" {
		fmt.Fprintln(stderr, "runopsy-agent: incidents list requires a valid --incident-dir")
		return 2
	}
	files, err := incident.List(*directory)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: incidents list: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%-38s %-20s %-24s %s\n", "ID", "TIME", "TRIGGER", "SIZE")
	for _, file := range files {
		fmt.Fprintf(stdout, "%-38s %-20s %-24s %s\n", file.ID, file.ModTime.Local().Format("Jan 02 15:04"), file.Trigger, humanBytes(uint64(max(file.Size, 0))))
	}
	return 0
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "runopsy-agent: validate requires exactly one bundle")
		return 2
	}
	bundle, err := incident.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: validate: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Bundle valid\nSchema: v%d\nSnapshots: %d\nEvents: %d\nIntegrity: OK\n", bundle.Manifest.SchemaVersion, len(bundle.Incident.Snapshots), len(bundle.Incident.Events))
	return 0
}

func runExtract(args []string, stdout, stderr io.Writer) int {
	var path string
	flagargs := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--output" {
			flagargs = append(flagargs, arg)
			if index+1 < len(args) {
				index++
				flagargs = append(flagargs, args[index])
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") && path == "" {
			path = arg
			continue
		}
		flagargs = append(flagargs, arg)
	}

	fs := flag.NewFlagSet("runopsy-agent extract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputdir := fs.String("output", "", "destination directory (default incident ID)")
	if err := fs.Parse(flagargs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "runopsy-agent: extract requires exactly one bundle")
		return 2
	}
	bundle, err := incident.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: extract: %v\n", err)
		return 1
	}
	dest := *outputdir
	if dest == "" {
		dest = bundle.Incident.ID
	}
	if err := incident.Extract(path, dest); err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: extract: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, dest)
	return 0
}
