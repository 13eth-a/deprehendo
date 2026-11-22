package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/incident"
)

// runTrigger asks a running recorder to freeze the configured pre/post window
// and waits for the bundle. the recorder keeps sampling throughout; only the
// incident is frozen.
func runTrigger(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent trigger", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.DefaultSocket(), "running agent control socket")
	note := fs.String("note", "", "short human annotation to attach to the incident")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "runopsy-agent: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	ctx := context.Background()
	response, err := agent.TriggerControlWithNote(ctx, *socket, *note)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: trigger: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Incident triggered\nID: %s\nCapturing %s post-trigger evidence...\n", response.ID, response.Window.PostTrigger)

	deadline := time.Now().Add(response.Window.PostTrigger + 30*time.Second)
	for {
		status, err := agent.IncidentStatusControlFor(ctx, *socket, response.ID)
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent: trigger: %v\n", err)
			return 1
		}
		if status.ID == response.ID {
			switch status.State {
			case incident.Complete:
				fmt.Fprintf(stdout, "Saved: %s\n", status.Path)
				return 0
			case incident.Failed:
				fmt.Fprintf(stderr, "runopsy-agent: incident save failed: %s\n", status.Error)
				if status.Path != "" {
					fmt.Fprintf(stderr, "Published artifact (durability uncertain): %s\n", status.Path)
				}
				return 1
			}
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(stderr, "runopsy-agent: incident %s not saved within %s\n", response.ID, response.Window.PostTrigger+30*time.Second)
			return 1
		}
		time.Sleep(100 * time.Millisecond)
	}
}
