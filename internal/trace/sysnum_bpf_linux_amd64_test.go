//go:build linux && amd64

package trace

// sysBPF is bpf(2) on linux/amd64. go's syscall package omits SYS_BPF there.
const sysBPF uint32 = 321
