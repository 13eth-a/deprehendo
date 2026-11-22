package agent

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// darwinExecutableName resolves the executable name of a live pid via
// `ps -o comm=`. ProcessDetail.Executable on macOS is the name only: the
// full path is not available without proc_pidinfo, which macOS does not let
// us call from go portably. empty means unknown.
func darwinExecutableName(ctx context.Context, pid int) string {
	if pid <= 0 {
		return ""
	}
	cmd := exec.CommandContext(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid))
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			return line
		}
	}
	if errors.Is(cmd.Err, context.Canceled) {
		return ""
	}
	return ""
}
