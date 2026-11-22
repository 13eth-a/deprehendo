package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkParseLinuxStat(b *testing.B) {
	raw := []byte(statFixture(42, 123))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseLinuxStat(42, raw); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkProcessesFixture100(b *testing.B) {
	root := b.TempDir()
	for i := 1; i <= 100; i++ {
		writeStatFixture(b, root, i, 123)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ProcessesAt(context.Background(), root); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkParseTCP100(b *testing.B) {
	input := strings.Repeat("0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n", 100)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseTCP(strings.NewReader(input)); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSocketOwnersFixture100(b *testing.B) {
	root := b.TempDir()
	for i := 1; i <= 100; i++ {
		writeStatFixture(b, root, i, 123)
		dir := filepath.Join(root, fmt.Sprint(i), "fd")
		if err := os.Mkdir(dir, 0755); err != nil {
			b.Fatal(err)
		}
		for fd := 0; fd < 4; fd++ {
			if err := os.Symlink(fmt.Sprintf("socket:[%d]", i*10+fd), filepath.Join(dir, fmt.Sprint(fd))); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := SocketOwners(root); err != nil {
			b.Fatal(err)
		}
	}
}
