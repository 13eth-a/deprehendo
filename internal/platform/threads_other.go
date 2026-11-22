//go:build !darwin

package platform

import "context"

func darwinThreadCountsContext(ctx context.Context) (map[int]int, error) { return nil, nil }
