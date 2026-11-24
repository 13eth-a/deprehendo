// command deprehendo-sim injects one simulated failure per invocation.
//
// this is fault-injection tooling only. recording and diagnosis arrive in
// phase 1.
//
// Underscore-prefixed names (e.g. `_node`) are internal helper processes used
// to build real process trees for the orphan and tree scenarios; they are
// intentionally absent from the scenario registry and help output.
package main

import (
	"os"
	"strings"

	"deprehendo/internal/simhelper"
	"deprehendo/internal/simulator"
)

func main() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "_") {
		os.Exit(simhelper.Run(os.Args[1:], os.Stderr))
	}
	os.Exit(simulator.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
