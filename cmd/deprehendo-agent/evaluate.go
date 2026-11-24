package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"strings"

	"deprehendo/internal/diagnosis"
)

func runEvaluate(args []string, stdout, stderr io.Writer) int {
	// accept flags before or after the directory, matching analyze.
	valueflags := map[string]bool{"--min-confidence": true, "--disable": true}
	var flagArgs, positional []string
	for index := 0; index < len(args); index++ {
		a := args[index]
		switch {
		case strings.HasPrefix(a, "-") && valueflags[a]:
			if index+1 >= len(args) {
				fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %s requires a value\n", a)
				return 2
			}
			flagArgs = append(flagArgs, a, args[index+1])
			index++
		case strings.HasPrefix(a, "-"):
			flagArgs = append(flagArgs, a)
		default:
			positional = append(positional, a)
		}
	}
	fs := flag.NewFlagSet("deprehendo-agent evaluate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonoutput := fs.Bool("json", false, "machine-readable JSON output")
	minConfidence := fs.Float64("min-confidence", diagnosis.DefaultMinConfidence, "minimum confidence to report a diagnosis")
	disable := fs.String("disable", "", "comma-separated signature IDs to exclude from evaluation")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	disabled, err := parseDisable(*disable)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %v\n", err)
		return 2
	}
	if len(positional) != 1 || math.IsNaN(*minConfidence) || *minConfidence < 0 || *minConfidence > 1 {
		fmt.Fprintln(stderr, "deprehendo-agent: evaluate requires exactly one fixture directory and 0 <= --min-confidence <= 1")
		return 2
	}
	result, err := diagnosis.EvaluateDirectory(positional[0], diagnosis.Options{MinConfidence: *minConfidence, Disable: disabled})
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %v\n", err)
		return 1
	}
	if *jsonoutput {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %v\n", err)
			return 1
		}
		data = append(data, '\n')
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %v\n", err)
			return 1
		}
		return 0
	}
	if err := diagnosis.WriteEvaluation(stdout, result); err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: evaluate: %v\n", err)
		return 1
	}
	return 0
}
