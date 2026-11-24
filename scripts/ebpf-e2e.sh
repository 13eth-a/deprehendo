#!/usr/bin/env bash
# live eBPF E2E (contract §2, §3.3, §3.5): run the tracer in debug mode
# pointed at a shell subtree, drive real processes through the cases below,
# then check what the kernel actually reported.
#
#   - exit(7), a child exec, and kill -TERM $$ (signal sent, exit by signal);
#   - SIGSTOP then SIGCONT to a watched child: the STOP and the single
#     RESUME must name the child, never its parent (§3.5);
#   - pidfd_send_signal: the SIGNAL_SENT must name the pidfd's process, not
#     a made-up process group (§3.3), when python3 has os.pidfd_open;
#   - an unwatched process stopped and resumed meanwhile must not appear;
#   - a dead PID in the watch set must not be reported as lost events.
#
# run on linux (lima VM / CI):  sudo -n scripts/ebpf-e2e.sh /path/to/deprehendo-trace
set -u
tracer="${1:?usage: $(basename "$0") /path/to/deprehendo-trace}"
work="$(mktemp -d /tmp/deprehendo-ebpf-e2e.XXXXXX)"
out="$work/events"
err="$work/stderr"

# A PID that no process holds right now, for the dead-watch check.
dead=$(( $(cat /proc/sys/kernel/pid_max) - 7 ))
while [ -e "/proc/$dead" ]; do dead=$((dead - 1)); done

# the watch target must outlive the whole exercise; its children become
# watched through the fork raw tracepoint, which is exactly what the agent
# relies on between watch-set syncs.
WORK="$work" sh -c '
  sleep 2                       # attach window: nothing forks before the tracer is up
  sh -c "exit 7" &              # grandchild: exit(7)
  wait $!
  sleep 30 & c=$!               # grandchild: stopped, then resumed, then killed
  echo "$c" > "$WORK/stopped_child"
  sleep 0.3; kill -STOP "$c"
  sleep 0.3; kill -CONT "$c"
  sleep 0.3; kill -TERM "$c"; wait "$c" 2>/dev/null
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$WORK/pidfd_target" <<PY 2>/dev/null
import os, signal, subprocess, sys, time
if not hasattr(os, "pidfd_open"):
    sys.exit(0)
p = subprocess.Popen(["sleep", "30"])
time.sleep(0.2)
open(sys.argv[1], "w").write(str(p.pid))
signal.pidfd_send_signal(os.pidfd_open(p.pid), signal.SIGTERM)
p.wait()
PY
  fi
  sleep 0.5
  sh -c "sleep 0.2; kill -TERM $$" &   # grandchild: kill -TERM $$
  wait $!
  sleep 3                       # stay alive for the tracer window
' &
watcher=$!
sleep 0.2 # let the watcher reach the attach-window sleep

# an unrelated process, never watched.
sleep 60 &
bystander=$!

sudo -n "$tracer" debug "$watcher" "$dead" > "$out" 2>"$err" &
tracer_pid=$!
sleep 2.5
kill -STOP "$bystander"; sleep 0.2; kill -CONT "$bystander"
sleep 4.5
echo "== in-kernel stats (fork/exec/exit/sent seen vs watched) =="
if sudo -n bpftool version >/dev/null 2>&1; then
  sudo -n bpftool map dump name stats 2>/dev/null | grep ',' | sed 's/^/  /'
else
  echo "  (bpftool not installed; skipped)"
fi
sudo -n kill -INT "$tracer_pid" 2>/dev/null
wait "$watcher" 2>/dev/null
kill "$bystander" 2>/dev/null
sleep 0.3

echo "== stderr =="
sed 's/^/  /' "$err"
echo "== events =="
sed 's/^/  /' "$out"

fail=0
need() { grep -qE "$1" "$out" || { echo "MISSING: $2"; fail=1; }; }
none() { if grep -qE "$1" "$out"; then echo "UNEXPECTED: $2"; fail=1; fi; }

need "SIGNAL_SENT" "SIGNAL_SENT (kill -TERM observed in-kernel)"
need "PROCESS_EXIT.*signal=15 fact=2" "PROCESS_EXIT by SIGTERM (fact=2)"
need "PROCESS_EXIT.*exit=7" "PROCESS_EXIT exit(7)"

c="$(cat "$work/stopped_child" 2>/dev/null)"
if [ -n "$c" ]; then
  need "^PROCESS_STOPPED pid=$c " "PROCESS_STOPPED naming the stopped child $c"
  resumed=$(grep -cE "^PROCESS_RESUMED pid=$c " "$out")
  [ "$resumed" -eq 1 ] || { echo "WRONG: $resumed PROCESS_RESUMED for child $c, want exactly 1"; fail=1; }
  none "^PROCESS_STOPPED pid=$watcher " "PROCESS_STOPPED naming the parent $watcher"
  none "^PROCESS_RESUMED pid=$watcher " "PROCESS_RESUMED naming the parent $watcher"
else
  echo "MISSING: the stop/resume child never ran"; fail=1
fi

none "^PROCESS_(STOPPED|RESUMED) pid=($bystander|$$) " "stop/resume of an unwatched process"

pt="$(cat "$work/pidfd_target" 2>/dev/null)"
if [ -n "$pt" ]; then
  need "^SIGNAL_SENT pid=$pt .*signal=15 .*pgid=0$" "pidfd SIGNAL_SENT naming its process $pt"
else
  echo "SKIP: pidfd check (python3 without os.pidfd_open)"
fi

if grep -q "events dropped" "$err"; then
  echo "UNEXPECTED: loss reported (a dead PID in the watch set must not count as lost events)"
  fail=1
fi

rm -rf "$work"
if [ "$fail" -eq 0 ]; then echo "EBPF-E2E-OK"; else echo "EBPF-E2E-FAILED"; exit 1; fi
