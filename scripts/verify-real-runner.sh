#!/usr/bin/env bash
# verify-real-runner.sh: collect the phase 5 facts that only a real
# self-hosted GitHub actions runner can confirm (audit blocker B3, item 5.42).
#
# usage:  scripts/verify-real-runner.sh RUNNER_ROOT [OUTPUT_FILE]
#
# RUNNER_ROOT is the directory that holds .runner, bin/ and _diag/.
# the report goes to OUTPUT_FILE (default ./runner-verification.txt).
#
# privacy: this script never opens .credentials, .credentials_rsaparams or
# .env; it reports only whether they exist. from .runner it prints key names
# and value types, never values. log lines are printed only after masking
# (hex, numbers, URLs, quoted text, job names). read the report before
# sharing it.
set -u

root="${1:-}"
out="${2:-./runner-verification.txt}"
if [ -z "$root" ] || [ ! -d "$root" ]; then
	echo "usage: $0 RUNNER_ROOT [OUTPUT_FILE]" >&2
	exit 2
fi
root="$(cd "$root" && pwd)"
umask 077
exec 3>"$out"

say() { printf '%s\n' "$*" >&3; }
section() { say ""; say "== $* =="; }

# mask: remove anything that could identify a repo, job, host or secret.
mask() {
	sed -E \
		-e 's#[a-zA-Z][a-zA-Z0-9+.-]*://[^ ]*#<url>#g' \
		-e 's#"[^"]*"#<q>#g' \
		-e "s#'[^']*'#<q>#g" \
		-e 's#[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}#<guid>#g' \
		-e 's#\b[0-9a-fA-F]{8,}\b#<hex>#g' \
		-e 's#(gh[opsru]_|github_pat_)[A-Za-z0-9_]+#<token>#g' \
		-e 's#Job .* completed with result#Job <name> completed with result#' \
		-e 's#Running job: .*#Running job: <name>#' \
		-e 's#(on|for|to) runner [^ ]+#\1 runner <name>#g' \
		-e 's#[0-9]+#<n>#g' |
		cut -c1-200
}

say "runopsy real-runner verification report"
say "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "platform:  $(uname -s) $(uname -m)"

section "1. Installation layout (existence only)"
for f in .runner .credentials .credentials_rsaparams .env run.sh config.sh svc.sh \
	bin/Runner.Listener bin/Runner.Worker bin/Runner.PluginHost _diag _work; do
	if [ -e "$root/$f" ]; then say "present  $f"; else say "absent   $f"; fi
done

section "2. .runner key names and value types (no values)"
if [ -f "$root/.runner" ]; then
	if head -c 3 "$root/.runner" | od -An -tx1 | grep -q 'ef bb bf'; then
		say "BOM: yes"
	else
		say "BOM: no"
	fi
	if command -v python3 >/dev/null 2>&1; then
		python3 -I - "$root/.runner" >&3 2>&1 <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8-sig") as f:
    data = json.load(f)
if not isinstance(data, dict):
    print("top level is", type(data).__name__)
else:
    for key in sorted(data):
        print(f"key {key!r}: {type(data[key]).__name__}")
PY
	elif command -v jq >/dev/null 2>&1; then
		sed '1s/^\xEF\xBB\xBF//' "$root/.runner" | jq -r 'to_entries[] | "key \(.key): \(.value|type)"' >&3
	else
		say "neither python3 nor jq is installed; key names not collected"
	fi
else
	say ".runner not found"
fi

section "3. Runner processes (role, name, executable under root?)"
os="$(uname -s)"
found=0
if [ "$os" = "Linux" ]; then
	for d in /proc/[0-9]*; do
		pid="${d#/proc/}"
		exe="$(readlink "$d/exe" 2>/dev/null || true)"
		comm="$(cat "$d/comm" 2>/dev/null || true)"
		base="${exe##*/}"
		case "$base$comm" in *Runner.Listener* | *Runner.Worker*) ;; *) continue ;; esac
		ppid="$(awk '{print $4}' "$d/stat" 2>/dev/null)"
		pcomm="$(cat "/proc/$ppid/comm" 2>/dev/null || echo '?')"
		under="no"
		case "$exe" in "$root"/*) under="yes" ;; esac
		say "comm=$comm exe_basename=$base exe_under_root=$under parent_comm=$pcomm"
		found=1
	done
elif [ "$os" = "Darwin" ]; then
	ps -axo pid=,ppid=,comm= | while read -r pid ppid comm; do
		base="${comm##*/}"
		case "$base" in Runner.Listener | Runner.Worker) ;; *) continue ;; esac
		pcomm="$(ps -o comm= -p "$ppid" 2>/dev/null)"
		under="no"
		case "$comm" in "$root"/*) under="yes" ;; esac
		say "ps_comm_basename=$base exe_under_root=$under parent_basename=${pcomm##*/}"
	done
	found=1
fi
[ "$found" = 1 ] || say "no Runner.Listener/Runner.Worker process seen (is the runner running?)"

section "4. _diag record shape"
shopt -s nullglob
runner_logs=("$root"/_diag/Runner_*.log)
worker_logs=("$root"/_diag/Worker_*.log)
logs=("${runner_logs[@]}" "${worker_logs[@]}")
if [ "${#logs[@]}" -eq 0 ]; then
	say "no _diag logs"
else
	say "files: Runner_*.log=${#runner_logs[@]} Worker_*.log=${#worker_logs[@]}"
	total=$(cat "${logs[@]}" | wc -l | tr -d ' ')
	shaped=$(grep -hcE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}Z [A-Z]{3,8} +[A-Za-z0-9_.]+\]' "${logs[@]}" | awk '{s+=$1} END {print s+0}')
	say "lines=$total matching_header=[YYYY-MM-DD HH:MM:SSZ LEVEL Component]: $shaped"
	say "level/component pairs (count):"
	grep -hoE '^\[[0-9-]{10} [0-9:]{8}Z [A-Z]{3,8} +[A-Za-z0-9_.]+\]' "${logs[@]}" |
		sed -E 's/^\[[^Z]*Z +//; s/\]$//; s/ +/ /' | sort | uniq -c | sort -rn | head -40 >&3
fi

section "5. Phrases the parser relies on (count per file scope)"
probe() { # label pattern file...
	local label="$1" pattern="$2" n=0
	shift 2
	# never call grep with no files: it would read stdin and hang.
	if [ "$#" -gt 0 ]; then
		n=$(cat "$@" | grep -cE "$pattern")
	fi
	say "$(printf '%-34s %6s' "$label" "$n")"
}
if [ "${#logs[@]}" -gt 0 ]; then
	probe "listener: Listening for Jobs" 'Listening for [Jj]obs' "${runner_logs[@]}"
	probe "listener: job request received" 'Job request [^ ]+ for plan [^ ]+ job [^ ]+ received|Received job message' "${runner_logs[@]}"
	probe "listener: Running job:" 'Running [Jj]ob: ' "${runner_logs[@]}"
	probe "any: completed with result" 'completed with result: ?[A-Za-z]+' "${runner_logs[@]}" "${worker_logs[@]}"
	probe "listener: cancellation to worker" 'Send job cancellation message to worker' "${runner_logs[@]}"
	probe "listener: connect error" '[Cc]onnect(ion)? error|Lost [Cc]onnection|disconnected from' "${runner_logs[@]}"
	probe "listener: reconnected" '[Rr]e-?connected' "${runner_logs[@]}"
	probe "listener: shutdown (UNVERIFIED)" '[Ss]hutting ?down|Stopping [Rr]unner|Runner service stopped|Received shutdown' "${runner_logs[@]}"
	probe "listener: update (UNVERIFIED)" '[Ss]oftware update|[Ss]elf-?update|Downloading the runner|Updating the runner|Runner update' "${runner_logs[@]}"
	probe "worker: cancelled (UNVERIFIED)" '[Jj]ob (was |has been )?cancell?ed|[Cc]ancell?ation (request|message) received' "${worker_logs[@]}"
	probe "worker: timed out (UNVERIFIED)" '[Jj]ob (has )?timed out|exceeded the maximum execution time' "${worker_logs[@]}"
fi

section "6. Masked lines for the UNVERIFIED events (review before sharing)"
if [ "${#logs[@]}" -gt 0 ]; then
	grep -hiE 'shut ?down|stopp|update|upgrade|cancel|timed out|timeout|exceeded|ephemeral|exit' "${logs[@]}" |
		grep -E '^\[' | sed -E 's/^\[[^]]*\] ?//' | mask | sort | uniq -c | sort -rn | head -60 >&3
fi

section "7. runopsy discovery (if runopsy-agent is on PATH)"
if command -v runopsy-agent >/dev/null 2>&1; then
	runopsy-agent github discover >&3 2>&1 || say "github discover exited non-zero"
else
	say "runopsy-agent not on PATH; skipped"
fi

exec 3>&-
echo "report written to $out (mode 0600). Read it before sharing."
