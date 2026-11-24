package github

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const tokenEnvironment = "DEPREHENDO_GITHUB_TOKEN"

// TokenSource obtains credentials at request time. it never includes token
// bytes in returned errors, logs, or persistent state.
type TokenSource struct {
	Path string
}

func (s TokenSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if token, ok := os.LookupEnv(tokenEnvironment); ok {
		token = strings.TrimSpace(token)
		if token == "" {
			return "", fmt.Errorf("github: %s is empty", tokenEnvironment)
		}
		return token, nil
	}
	path := s.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("github: no token source configured")
		}
		path = filepath.Join(home, ".deprehendo", "github-token")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("github: token file unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("github: token file must be a regular file with mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return "", fmt.Errorf("github: token file must be owned by the agent user")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("github: token file unavailable")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("github: token file is empty or malformed")
	}
	return token, nil
}
