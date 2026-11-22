package github

import "testing"

func TestInstallRootFromExe(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		want string
	}{
		{"plain bin layout", "/opt/actions-runner/bin/Runner.Listener", "/opt/actions-runner"},
		{"versioned bin layout", "/home/u/actions-runner/bin.2.338.0/Runner.Listener", "/home/u/actions-runner"},
		{"not under bin", "/tmp/impostor/Runner.Listener", ""},
		{"binary name only", "/tmp/bin-tools/Runner.Listener", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := installRootFromExe(tc.exe); got != tc.want {
				t.Fatalf("installRootFromExe(%q) = %q, want %q", tc.exe, got, tc.want)
			}
		})
	}
}
