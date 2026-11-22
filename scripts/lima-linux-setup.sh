#!/usr/bin/env bash
# prepare a linux VM (lima or any Ubuntu/Debian host) to run the repo's tests
# as CI does, and optionally register a self-hosted GitHub actions runner.
#
# usage (inside the VM, from the repo root):
#   scripts/lima-linux-setup.sh toolchain
#   scripts/lima-linux-setup.sh test
#   scripts/lima-linux-setup.sh runner <owner/repo> <registration-token>
#
# toolchain  installs git, curl, build tools and the go version in go.mod
# test       runs the same command CI runs (as root; see ci.yml)
# runner     downloads and configures an actions runner in ~/actions-runner
#            and installs it as a service. the registration token is a
#            short-lived value from settings > actions > runners > new runner.
#
# nothing here starts the runner service on its own; `runner` only configures
# it. start it with: cd ~/actions-runner && sudo ./svc.sh start

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# toolchain installs go to /usr/local/go; use it even when the current shell
# has not been given that PATH entry yet.
if [ -d /usr/local/go/bin ]; then
  export PATH="/usr/local/go/bin:$PATH"
fi
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner}"
RUNNER_VERSION="${RUNNER_VERSION:-2.329.0}"

die() { echo "error: $*" >&2; exit 1; }

go_version() {
  awk '/^go /{print $2; exit}' "$REPO_ROOT/go.mod"
}

cmd_toolchain() {
  command -v apt-get >/dev/null || die "apt-get not found; this script targets Ubuntu/Debian"
  sudo apt-get update
  sudo apt-get install -y build-essential git curl ca-certificates

  local want
  want="$(go_version)"
  [ -n "$want" ] || die "could not read the Go version from go.mod"

  if command -v go >/dev/null && [ "$(go env GOVERSION 2>/dev/null)" = "go$want" ]; then
    echo "go$want already installed"
    return
  fi

  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  echo "installing go$want ($arch) to /usr/local/go"
  curl -fsSL "https://go.dev/dl/go${want}.linux-${arch}.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
  echo "add /usr/local/go/bin to PATH (e.g. in ~/.profile), then check: go version"
}

cmd_test() {
  cd "$REPO_ROOT"
  command -v go >/dev/null || die "go not found; run the toolchain step first"
  # matches .github/workflows/ci.yml: root is needed because internal/platform
  # reads /proc/1/fd.
  sudo env "PATH=$PATH" "GOCACHE=$(go env GOCACHE)" "GOMODCACHE=$(go env GOMODCACHE)" \
    go test -race -count=1 -timeout=5m ./...
}

cmd_runner() {
  local repo="${1:-}" token="${2:-}"
  [ -n "$repo" ] && [ -n "$token" ] || die "usage: runner <owner/repo> <registration-token>"
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac

  mkdir -p "$RUNNER_DIR"
  cd "$RUNNER_DIR"
  if [ ! -x ./config.sh ]; then
    curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${arch}-${RUNNER_VERSION}.tar.gz" -o runner.tgz
    tar xzf runner.tgz
    rm -f runner.tgz
  fi
  ./config.sh --unattended --url "https://github.com/${repo}" --token "$token" \
    --name "runopsy-$(hostname)" --labels "runopsy-linux" --replace
  sudo ./svc.sh install
  echo "runner configured in $RUNNER_DIR (not started). Start: cd $RUNNER_DIR && sudo ./svc.sh start"
}

case "${1:-}" in
  toolchain) cmd_toolchain ;;
  test) cmd_test ;;
  runner) shift; cmd_runner "$@" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
