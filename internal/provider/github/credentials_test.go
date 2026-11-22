package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenSourceReadsPrivateFileAndRejectsUnsafeModes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("canary-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := (TokenSource{Path: path}).Token(context.Background())
	if err != nil || token != "canary-token" {
		t.Fatalf("Token() = %q, %v", token, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if token, err := (TokenSource{Path: path}).Token(context.Background()); err == nil || token != "" || strings.Contains(err.Error(), "canary-token") {
		t.Fatalf("unsafe file mode accepted or token leaked: token=%q err=%v", token, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if token, err := (TokenSource{Path: path}).Token(context.Background()); err == nil || token != "" {
		t.Fatalf("symlink token file accepted: token=%q err=%v", token, err)
	}
}

func TestTokenSourceEnvironmentAndCancellation(t *testing.T) {
	t.Setenv(tokenEnvironment, "env-canary")
	token, err := (TokenSource{Path: filepath.Join(t.TempDir(), "absent")}).Token(context.Background())
	if err != nil || token != "env-canary" {
		t.Fatalf("environment token = %q, %v", token, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if token, err := (TokenSource{}).Token(ctx); err == nil || token != "" {
		t.Fatalf("cancelled token lookup = %q, %v", token, err)
	}
}
