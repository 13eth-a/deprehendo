#!/usr/bin/env bash
# 7.62, hosted half: push real-runner bundles through the deployed product.
#
#   bash scripts/demo-verify-hosted.sh ~/demo-out/7.62-oom.runopsy ~/demo-out/7.62-stall.runopsy
#
# for each bundle: analyze it locally (`analyze --document`), upload it with
# your normal login (`runopsy-agent upload`), wait for the hosted analysis,
# and require the hosted /analysis to be byte-identical to the local document.
# then it prints the dashboard link to open.
#
# the byte check needs the same engine on both sides: build bin/ from the
# commit railway is running (`git pull && make build`).
# the token is read from the agent's config into a private header file and is
# never printed.
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG=${RUNOPSY_CONFIG:-"$HOME/Library/Application Support/runopsy/config.json"}
DASHBOARD=${RUNOPSY_DASHBOARD:-https://web-production-d673c0ef.up.railway.app}
die() { echo "FAIL: $*" >&2; exit 1; }
# --replace deletes each bundle's incident first (owner token), so it is
# analyzed again by the deployed analyzer instead of keeping its old analysis.
REPLACE=0
if [ "${1:-}" = --replace ]; then REPLACE=1; shift; fi
[ $# -ge 1 ] || die "usage: bash scripts/demo-verify-hosted.sh [--replace] BUNDLE..."
[ -x bin/runopsy-agent ] || die "run 'make build' first"
[ -f "$CONFIG" ] || die "agent config not found: $CONFIG (run bin/runopsy-agent login first)"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/runopsy-demo-verify.XXXXXX")
HDR="$WORK/.auth"
trap 'rm -f "$HDR"' EXIT
API=$( (umask 077; python3 -I - "$CONFIG" "$HDR" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write("Authorization: Bearer " + c["token"] + "\n")
print(c["endpoint"].rstrip("/"))
PY
) ) || die "could not read endpoint and token from $CONFIG"

failed=0
for bundle in "$@"; do
  [ -f "$bundle" ] || die "no such bundle: $bundle"
  name=$(basename "$bundle" .runopsy)
  echo "== $name"
  bin/runopsy-agent analyze --document "$WORK/$name.local.json" "$bundle" >/dev/null || die "local analysis of $bundle failed"
  if [ "$REPLACE" = 1 ]; then
    old=$(grep -oE 'inc_[0-9a-f]{32}' "$WORK/$name.local.json" | head -1 || true)
    if [ -n "$old" ]; then
      code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H @"$HDR" "$API/api/incidents/$old" || echo 000)
      case "$code" in
        200) echo "  deleted the earlier upload $old" ;;
        404) ;;
        *) die "deleting $old answered $code (replacing needs an owner token)" ;;
      esac
    fi
  fi
  out=$(bin/runopsy-agent upload -config "$CONFIG" "$bundle" 2>&1) || { echo "$out"; die "upload of $bundle failed"; }
  echo "$out" | sed 's/^/  /'
  id=$(printf '%s\n' "$out" | grep -oE 'inc_[0-9a-f]{32}' | head -1 || true)
  [ -n "$id" ] || id=$(grep -oE 'inc_[0-9a-f]{32}' "$WORK/$name.local.json" | head -1 || true)
  [ -n "$id" ] || die "could not find the incident id for $bundle"
  code=000
  for _ in $(seq 1 30); do
    code=$(curl -sS -o "$WORK/$name.hosted.json" -w '%{http_code}' -H @"$HDR" "$API/api/incidents/$id/analysis" || echo 000)
    [ "$code" = 200 ] && break
    sleep 2
  done
  [ "$code" = 200 ] || die "$id: hosted analysis answered $code"
  if cmp -s "$WORK/$name.local.json" "$WORK/$name.hosted.json"; then
    echo "  PASS: hosted /analysis is byte-identical to the local document"
  else
    echo "  FAIL: hosted /analysis differs from the local document (is bin/ built from the deployed commit?)"
    failed=1
  fi
  python3 -I - "$WORK/$name.hosted.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
m = (d.get("diagnosis") or {}).get("matches") or []
labels = sorted({s.get("Label", "") for p in d.get("providers") or [] for s in p.get("Signatures") or []})
print("  diagnosis:", m[0]["signature"] if m else "UNKNOWN", "| provider signatures:", " ".join(labels) or "none")
PY
  echo "  open: $DASHBOARD/incidents/$id"
done
[ "$failed" = 0 ] || die "at least one hosted document differs"
echo
echo "ALL PASS. Open the links above, signed in, and check each page renders."
