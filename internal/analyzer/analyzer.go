// package analyzer is the phase 7 analyzer worker's engine half (contract
// docs/cloud/contract.md §5.4): one child process per bundle, hostile input
// through the unmodified phase 2 reader, one document out, and explicit job
// statuses instead of ambiguous stderr prose.
//
// the child is the only code that touches bundle bytes. it self-limits
// (CPU, open files), starts with no environment except GOMEMLIMIT, runs in a
// private directory it need not write to, and never prints bundle content:
// rejections are classified reasons, and the parent truncates diagnostics.
// the network, the filesystem beyond stdin/stdout, and web's credentials do
// not exist for it.
package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"deprehendo/internal/analysis"
	"deprehendo/internal/incident"
)

// exit codes of the child process. they are the statuses' machine contract;
// anything else the child exits with is FAILED_CRASH, not REJECTED.
const (
	ExitOK       = 0 // document on stdout
	ExitRejected = 3 // the reader refused the bundle; reason on stderr
	ExitLimited  = 4 // the child could not install its own limits
)

// maxStdinRead bounds what the child ever reads from stdin: one archive
// budget plus one byte to detect the attempt.
const maxStdinRead = incident.MaxPayloadBytes + (1 << 20) + 1

// child runs the analysis child process in-process: bundle bytes on the
// reader, document on the writer, classified reason on the error writer. the
// child command in cmd/deprehendo-analyzer wires real descriptors to this; tests
// call it directly.
//
// byte accounting is deliberate: stdin is read with a limit one byte past
// the archive budget, so an oversized hostile bundle fails fast instead of
// paging memory; the document is written once.
func Child(stdin io.Reader, stdout, stderr io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxStdinRead))
	if err != nil {
		fmt.Fprintf(stderr, "analyzer: read bundle: %v\n", err)
		return ExitRejected
	}
	if len(raw) == maxStdinRead {
		fmt.Fprintln(stderr, "analyzer: Rejected: archive exceeds the 64MiB+1MiB bundle budget")
		return ExitRejected
	}
	if len(raw) < 22 {
		fmt.Fprintln(stderr, "analyzer: Rejected: truncated archive")
		return ExitRejected
	}
	bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		// the reader's message may describe the hostile input; class it and
		// keep the detail on stderr, which the parent truncates. it never
		// echoes payload bytes (the messages are static formats).
		fmt.Fprintf(stderr, "analyzer: Rejected: %v\n", err)
		return ExitRejected
	}
	sum := sha256.Sum256(raw)
	doc, err := analysis.Run(bundle, hex.EncodeToString(sum[:]), analysis.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "analyzer: Failed: %v\n", err)
		return ExitRejected
	}
	if err := analysis.WriteJSON(stdout, doc); err != nil {
		fmt.Fprintf(stderr, "analyzer: Failed: %v\n", err)
		return ExitRejected
	}
	return ExitOK
}
