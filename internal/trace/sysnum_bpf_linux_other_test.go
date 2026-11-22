//go:build linux && !amd64 && !arm64

package trace

// sysBPF is unknown on this architecture; the seccomp test is skipped.
const sysBPF = ^uint32(0)
