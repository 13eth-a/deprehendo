//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os/exec"
)

// darwinThreadCounts asks ps for all per-thread rows in one invocation.
// processes can exit between the process and thread listings, so missing
// counts are best-effort zeros in the sampled process records.
func darwinThreadCountsContext(ctx context.Context) (map[int]int, error) {
	out, err := exec.CommandContext(ctx, "/bin/ps", "-M", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps thread listing: %w", err)
	}
	return parseDarwinThreadCounts(out), nil
}
