//go:build linux && arm64

package trace

// sysBPF is bpf(2) on linux/arm64 (also syscall.SYS_BPF there).
const sysBPF uint32 = 280
