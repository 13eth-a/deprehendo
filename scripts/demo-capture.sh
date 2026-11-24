#!/usr/bin/env bash
# 7.62: capture the two traced headline demos on a DISPOSABLE VM runner.
#
#   sudo bash scripts/demo-capture.sh oom     # then dispatch scenario=memory
#   sudo bash scripts/demo-capture.sh stall   # runner idle; blocks HTTPS 3 min
#
# both modes start `deprehendo-agent github watch --tracing auto` (eBPF, falling
# back to the proc connector), check what the capture shows, and copy the
# bundle and its reports to ~/demo-out for the hosted check on the Mac.
#
#   oom    trigger on process exit, 250 ms samples. expect the engine's
#          diagnosis OOM_KILL (kernel OOM counter / OOM record in the bundle).
#   stall  record an idle runner for 90 s, drop outbound HTTPS for 3 minutes,
#          capture, restore HTTPS. expect the GitHub provider signature
#          GITHUB_RUNNER_COMMUNICATION_STALL; the generic diagnosis abstains
#          (UNKNOWN), by design.
#
# never run this on a production runner: the stall mode cuts all outbound
# HTTPS from the machine for three minutes (it is always restored on exit).
# paths: DEPREHENDO_BIN (default ~/deprehendo-bin of the sudo user) must hold
# deprehendo-agent and deprehendo-trace. STALL_BASELINE_SECONDS (90) and
# STALL_BLOCK_SECONDS (180) exist for testing; keep the defaults for the demo.
set -euo pipefail

MODE=${1:-}
die() { echo "FAIL: $*" >&2; exit 1; }
case "$MODE" in oom|stall) ;; *) die "usage: sudo bash scripts/demo-capture.sh oom|stall" ;; esac
[ "$(id -u)" = 0 ] || die "run with sudo: the tracer and the HTTPS block need root"
command -v python3 >/dev/null || die "python3 is required"

U=${SUDO_USER:-root}
UHOME=$(getent passwd "$U" | cut -d: -f6)
BIN=${DEPREHENDO_BIN:-$UHOME/deprehendo-bin}
AGENT=$BIN/deprehendo-agent
[ -x "$AGENT" ] || die "$AGENT not found; build it first (runbook step 3)"
[ -x "$BIN/deprehendo-trace" ] || die "$BIN/deprehendo-trace not found; the demo must be traced (runbook step 3)"
pgrep -f Runner.Listener >/dev/null || die "no Runner.Listener is running; start the runner (./run.sh) first"

TS=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/var/tmp/deprehendo-demo/$MODE-$TS
mkdir -p "$WORK"
chmod 700 "$WORK"
# the agent refuses an incident directory that is not private (0700).
install -d -m 0700 "$WORK/incidents"
OUT=$UHOME/demo-out
install -d -o "$U" -m 0755 "$OUT"
SOCK=$WORK/agent.sock
WATCH=""
BLOCKED=0

cleanup() {
  if [ "$BLOCKED" = 1 ]; then
    iptables -D OUTPUT -p tcp --dport 443 -j DROP 2>/dev/null || true
    echo "HTTPS restored"
  fi
  [ -n "$WATCH" ] && stop_watch
  return 0
}

# stop_watch: ask the watcher to stop, then insist. A background job of a
# script may ignore SIGINT, so never wait on it unbounded.
stop_watch() {
  local sig i
  for sig in INT TERM KILL; do
    kill -"$sig" "$WATCH" 2>/dev/null || break
    for i in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$WATCH" 2>/dev/null || break 2
      sleep 0.5
    done
  done
  wait "$WATCH" 2>/dev/null || true
  WATCH=""
}
trap cleanup EXIT

start_watch() {
  "$AGENT" github watch --tracing auto --incident-dir "$WORK/incidents" --socket "$SOCK" "$@" \
    > "$WORK/agent.log" 2>&1 &
  WATCH=$!
  for _ in $(seq 1 60); do
    if grep -q 'Recording' "$WORK/agent.log"; then
      grep -E 'Platform|Tracing|Watching|Automatic triggers|Incident capture' "$WORK/agent.log" | sed 's/^/  /'
      return 0
    fi
    kill -0 "$WATCH" 2>/dev/null || { cat "$WORK/agent.log"; die "github watch exited"; }
    sleep 1
  done
  cat "$WORK/agent.log"
  die "github watch did not start recording within 60 s"
}

# doc_of BUNDLE -> path of its analysis document. fails while the bundle does
# not analyze; the error is kept in BUNDLE's .err file for the report below.
doc_of() {
  local d="$WORK/$(basename "$1" .deprehendo).json"
  "$AGENT" analyze --document "$d" "$1" >/dev/null 2>"$d.err" && printf '%s' "$d"
}
verdict() {
  python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
m = (d.get("diagnosis") or {}).get("matches") or []
print(m[0]["signature"] if m else "UNKNOWN")' "$1"
}
provider_labels() {
  python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(" ".join(sorted({s.get("Label", "") for p in d.get("providers") or [] for s in p.get("Signatures") or []})) or "none")' "$1"
}

# keep BUNDLE NAME -> copy the bundle and its reports to ~/demo-out
keep() {
  local b=$1 name=$2
  install -o "$U" -m 0644 "$b" "$OUT/$name.deprehendo"
  "$AGENT" analyze --report "$b" > "$OUT/$name.analyze.txt" 2>&1 || true
  "$AGENT" timeline --report "$b" > "$OUT/$name.timeline.txt" 2>&1 || true
  "$AGENT" analyze --document "$OUT/$name.document.json" "$b" >/dev/null 2>&1 || true
  chown "$U" "$OUT/$name".*
  echo
  echo "Saved to $OUT:"
  ls -l "$OUT/$name".* | sed 's/^/  /'
  echo
  echo "Tracer lines from the report (check it was active, not disabled or unavailable):"
  grep -iE 'trac' "$OUT/$name.analyze.txt" | head -8 | sed 's/^/  /' || echo "  (no tracer lines in the report)"
}

if [ "$MODE" = oom ]; then
  echo "Starting a traced watch with exit triggers (250 ms samples)"
  start_watch --interval 250ms --window 180s --capture-pre 90s --capture-post 10s --trigger-on-process-exit
  echo
  echo "Now dispatch the job: GitHub -> 13eth-a/deprehendo-runner-e2e -> Actions -> deprehendo-b3 -> Run workflow -> scenario: memory"
  echo "  (or on the Mac: gh workflow run deprehendo-b3 -R 13eth-a/deprehendo-runner-e2e -f scenario=memory)"
  echo "Waiting up to 15 minutes for a capture whose diagnosis is OOM_KILL..."
  checked=" "
  tries=" "
  last_note=0
  deadline=$(( $(date +%s) + 900 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for b in "$WORK"/incidents/*.deprehendo; do
      [ -e "$b" ] || continue
      case "$checked" in *" $b "*) continue ;; esac
      sleep 2
      if ! d=$(doc_of "$b"); then
        # give a bundle that is still being written three tries, then report it.
        tries="$tries$b "
        n=$( { printf '%s' "$tries" | grep -o " $b " || true; } | wc -l | tr -d ' ')
        if [ "$n" -ge 3 ]; then
          checked="$checked$b "
          echo "  capture $(basename "$b"): could not be analyzed:"
          sed 's/^/    /' "$WORK/$(basename "$b" .deprehendo).json.err" | head -5
        fi
        continue
      fi
      checked="$checked$b "
      v=$(verdict "$d")
      echo "  capture $(basename "$b"): diagnosis $v"
      if [ "$v" = OOM_KILL ]; then
        keep "$b" 7.62-oom
        echo
        echo "PASS: OOM_KILL captured. Copy ~/demo-out to the Mac (runbook step 6)."
        exit 0
      fi
    done
    # once a minute, say what the watch has seen, so silence is never ambiguous.
    now_s=$(date +%s)
    if [ $((now_s - last_note)) -ge 60 ]; then
      last_note=$now_s
      # ls exits 1 while there are no captures yet; that must count as zero.
      n=$( { ls "$WORK"/incidents/*.deprehendo 2>/dev/null || true; } | wc -l | tr -d ' ')
      kill -0 "$WATCH" 2>/dev/null || { tail -20 "$WORK/agent.log"; die "github watch stopped"; }
      echo "  $(date -u +%H:%M:%SZ) watch running; $n capture(s) so far"
    fi
    sleep 5
  done
  echo "Last lines of the agent log:"
  grep -v 'level=DEBUG' "$WORK/agent.log" | tail -15 | sed 's/^/  /'
  die "no OOM_KILL capture within 15 minutes; captures and agent.log are in $WORK"
fi

# stall
echo "Starting a traced watch for an idle-runner communication stall"
start_watch --interval 1s --window 330s --capture-pre 300s --capture-post 20s
echo
echo "Do not dispatch any job during this run."
BASELINE=${STALL_BASELINE_SECONDS:-90}
BLOCK=${STALL_BLOCK_SECONDS:-180}
echo "Recording an idle baseline for ${BASELINE} s..."
sleep "$BASELINE"
iptables -I OUTPUT -p tcp --dport 443 -j DROP
BLOCKED=1
echo "$(date -u +%H:%M:%SZ) outbound HTTPS blocked; holding for ${BLOCK} s..."
sleep "$BLOCK"
"$AGENT" trigger --socket "$SOCK" --note "7.62 idle runner: outbound HTTPS blocked for 3 minutes" >/dev/null
echo "$(date -u +%H:%M:%SZ) capture triggered"
sleep 2
iptables -D OUTPUT -p tcp --dport 443 -j DROP
BLOCKED=0
echo "$(date -u +%H:%M:%SZ) HTTPS restored; waiting for the bundle..."
for _ in $(seq 1 45); do
  b=$(ls "$WORK"/incidents/*.deprehendo 2>/dev/null | head -1 || true)
  if [ -n "$b" ]; then
    sleep 2
    d=$(doc_of "$b") || { sleep 2; continue; }
    v=$(verdict "$d")
    labels=$(provider_labels "$d")
    echo "  capture $(basename "$b"): diagnosis $v; provider signatures: $labels"
    keep "$b" 7.62-stall
    case " $labels " in
      *" GITHUB_RUNNER_COMMUNICATION_STALL "*)
        echo
        echo "PASS: GITHUB_RUNNER_COMMUNICATION_STALL recorded (generic diagnosis: $v). Copy ~/demo-out to the Mac (runbook step 6)."
        exit 0 ;;
    esac
    die "the capture has no GITHUB_RUNNER_COMMUNICATION_STALL; send $OUT/7.62-stall.analyze.txt"
  fi
  sleep 2
done
die "no bundle was written within 90 s of the trigger; agent.log is in $WORK"
