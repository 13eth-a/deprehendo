// pressure stall information parsing. the parser is portable and
// fixture-testable; the /proc/pressure readers are Linux-only.
package platform

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// pressure is one PSI line ("some"/"full") with its windowed percentages.
// standard PSI windows are 10, 60 and 300 seconds; Avg600 is retained for
// compatibility with extended fixtures, not a standard kernel field.
type Pressure struct {
	TotalMicros uint64  `json:"total_us"`
	Avg10       float64 `json:"avg10"`
	Avg60       float64 `json:"avg60"`
	Avg300      float64 `json:"avg300"`
	Avg600      float64 `json:"avg600,omitempty"`
}

// PressureSnapshot is one /proc/pressure/{cpu,memory,io} reading. the CPU
// resource may omit "full" on older kernels; HasFull
// distinguishes an absent line from a genuinely quiet full-pressure value.
type PressureSnapshot struct {
	HasSome bool     `json:"has_some"`
	Some    Pressure `json:"some"`
	Full    Pressure `json:"full"`
	HasFull bool     `json:"has_full"`
}

// resource identifies one PSI file inside /proc/pressure.
type Resource string

const (
	PressureCPU    Resource = "cpu"
	PressureMemory Resource = "memory"
	PressureIO     Resource = "io"
)

// ReadPressure reads one /proc/pressure/<resource> file. other platforms
// return an explicit not-implemented error.
func ReadPressure(resource Resource) (PressureSnapshot, error) {
	if resource != PressureCPU && resource != PressureMemory && resource != PressureIO {
		return PressureSnapshot{}, fmt.Errorf("platform: unknown pressure resource %q", resource)
	}
	if runtime.GOOS != "linux" {
		return PressureSnapshot{}, fmt.Errorf("platform: pressure not implemented on %s", runtime.GOOS)
	}
	f, err := os.Open("/proc/pressure/" + string(resource))
	if err != nil {
		return PressureSnapshot{}, fmt.Errorf("platform: open pressure %s: %w", resource, err)
	}
	defer f.Close()
	return ParsePressure(f)
}

// ParsePressure parses the PSI textual format from any reader, including
// fixture files. an absent "full" line is normal (CPU), not an error.
func ParsePressure(r io.Reader) (PressureSnapshot, error) {
	snapshot := PressureSnapshot{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return snapshot, fmt.Errorf("platform: malformed pressure line %q", line)
		}
		first, rest := parts[0], strings.Join(parts[1:], " ")
		switch first {
		case "some":
			if snapshot.HasSome {
				return snapshot, fmt.Errorf("platform: duplicate some pressure line")
			}
			pressure, err := parsePressureAverages(rest)
			if err != nil {
				return snapshot, err
			}
			snapshot.Some = pressure
			snapshot.HasSome = true
		case "full":
			if snapshot.HasFull {
				return snapshot, fmt.Errorf("platform: duplicate full pressure line")
			}
			pressure, err := parsePressureAverages(rest)
			if err != nil {
				return snapshot, err
			}
			snapshot.Full = pressure
			snapshot.HasFull = true
		default:
			return snapshot, fmt.Errorf("platform: unexpected pressure kind %q", first)
		}
	}
	if err := scanner.Err(); err != nil {
		return snapshot, err
	}
	if !snapshot.HasSome {
		return snapshot, fmt.Errorf("platform: pressure missing some line")
	}
	return snapshot, nil
}

// parsePressureAverages parses "avg10=.. avg60=.. avg300=.. [avg600=..] total=N".
func parsePressureAverages(s string) (Pressure, error) {
	var p Pressure
	seen := make(map[string]bool)
	for _, field := range strings.Fields(s) {
		key, value, found := strings.Cut(field, "=")
		if !found {
			return p, fmt.Errorf("platform: pressure field %q", field)
		}
		if seen[key] {
			return p, fmt.Errorf("platform: duplicate pressure field %q", key)
		}
		seen[key] = true
		switch key {
		case "avg10", "avg60", "avg300", "avg600":
			v, err := strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
				return p, fmt.Errorf("platform: pressure %s invalid percentage %q", key, value)
			}
			switch key {
			case "avg10":
				p.Avg10 = v
			case "avg60":
				p.Avg60 = v
			case "avg300":
				p.Avg300 = v
			case "avg600":
				p.Avg600 = v
			}
		case "total":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return p, fmt.Errorf("platform: pressure total: %w", err)
			}
			p.TotalMicros = v
		default:
			return p, fmt.Errorf("platform: pressure field %q", field)
		}
	}
	for _, key := range []string{"avg10", "avg60", "avg300", "total"} {
		if !seen[key] {
			return p, fmt.Errorf("platform: pressure missing %s", key)
		}
	}
	return p, nil
}
