#!/usr/bin/env bash
# load the deployed stack to 1, 100 and 1,000 incidents for real bills (7.59).
#
#   bash scripts/cost-load.sh                 # load in stages, pause at each
#   bash scripts/cost-load.sh cleanup DIR     # delete everything a run made
#
# the load uses throwaway organizations named costload-<run>-NN, each holding
# the checked-in bundles in testdata/incidents (19 today). many small orgs keep
# every org far under the 60 analyses/org/hour limit, so 1,000 uploads finish
# in one sitting. uploads go through the real CLI to the deployed API, so each
# one is a real create, storage POST and complete, with the analysis run on
# Railway.
#
# at each stage the script records what it can measure itself (uploads, wall
# time, upload latency, database size, bucket objects and bytes), then pauses so
# you can read the railway and neon usage pages and type the figures in.
#
# cleanup deletes every incident of the run's orgs through the API (objects
# first, then rows), deletes the orgs (tokens, memberships and usage rows go
# with them by cascade), checks nothing is left, and removes the token files.
# it touches only orgs whose id is listed in DIR/orgs.txt AND whose name starts
# with the run's costload- prefix.
#
# secrets are never printed: owner tokens go straight into 0600 config files.
# overrides: RUNOPSY_API, RUNOPSY_S3_BUCKET, STAGES ("1 100 1000"), OUT.
set -euo pipefail
cd "$(dirname "$0")/.."

API=${RUNOPSY_API:-https://runopsy.up.railway.app}
BUCKET=${RUNOPSY_S3_BUCKET:-runopsy-0uz5hzbri3moxaaaa}
STAGES=${STAGES:-"1 100 1000"}
FIXTURES_DIR=testdata/incidents
MODE=${1:-run}

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for c in psql curl python3 openssl; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
[ -x bin/runopsy-agent ] && [ -x bin/runopsy-cloud ] || die "run 'make build' first"
[ -f .env.local ] || die ".env.local not found in the repo root"
set -a
# shellcheck disable=SC1091
. ./.env.local
set +a
DSN=${DATABASE_URL_UNPOOLED:-}
[ -n "$DSN" ] || die "DATABASE_URL_UNPOOLED is not set in .env.local"

q() { psql "$DSN" -XqtAc "$1"; }
now() { python3 -I -c 'import time; print(f"{time.time():.3f}")'; }

HAVE_AWS=0
if command -v aws >/dev/null 2>&1 && [ -f .env.railway ]; then HAVE_AWS=1; fi
# s3 ARGS: the aws CLI against the railway bucket. .env.local carries neon's
# own storage settings (AWS_ENDPOINT_URL_S3 and keys from `neon deploy`), so
# every inherited AWS variable is cleared before .env.railway is loaded.
s3() {
  (
    for v in $(env | sed -n 's/^\(AWS_[A-Z0-9_]*\)=.*/\1/p'); do unset "$v"; done
    set -a
    # shellcheck disable=SC1091
    . ./.env.railway
    set +a
    export AWS_REGION="${AWS_REGION:-auto}" AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-${AWS_REGION:-auto}}"
    aws --endpoint-url "${AWS_ENDPOINT_URL_S3:-https://t3.storageapi.dev}" s3 "$@"
  )
}

# header_for CONFIG -> path of a private curl header file holding its token
header_for() {
  local cfg=$1 hdr="$1.hdr"
  if [ ! -f "$hdr" ]; then
    ( umask 077; python3 -I - "$cfg" "$hdr" <<'PY'
import json, sys
open(sys.argv[2], "w").write("Authorization: Bearer " + json.load(open(sys.argv[1]))["token"] + "\n")
PY
    )
  fi
  printf '%s' "$hdr"
}

# ------------------------------------------------------------------ cleanup
cleanup() {
  local dir=$1
  [ -f "$dir/run.txt" ] && [ -f "$dir/orgs.txt" ] || die "$dir is not a cost-load run directory"
  local run
  run=$(cat "$dir/run.txt")
  case "$run" in costload-*) ;; *) die "unexpected run prefix '$run' in $dir/run.txt" ;; esac
  echo "Cleaning up run $run ($(wc -l < "$dir/orgs.txt" | tr -d ' ') orgs) from $dir"
  local deleted=0 failed=0 id name cfg hdr inc code ids
  while read -r id name cfg; do
    case "$name" in "$run"-*) ;; *) die "org $id is named '$name', not $run-*: refusing to touch it" ;; esac
    # A finished earlier cleanup removed the token file; its org is gone too.
    [ -f "$cfg" ] || continue
    hdr=$(header_for "$cfg")
    # up to 200 incidents per page; a run puts at most 19 in an org.
    ids=$(curl -sS -H @"$hdr" "$API/api/incidents?limit=200" </dev/null | python3 -I -c '
import json, sys
try:
    rows = json.load(sys.stdin)
    for r in rows if isinstance(rows, list) else []:
        print(r["incident_id"])
except Exception:
    pass')
    for inc in $ids; do
      code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H @"$hdr" "$API/api/incidents/$inc" </dev/null || echo 000)
      if [ "$code" = 200 ]; then deleted=$((deleted + 1)); else failed=$((failed + 1)); echo "  delete $inc in $name answered $code"; fi
    done
  done < "$dir/orgs.txt"
  echo "API deletes: $deleted ok, $failed failed"
  [ "$failed" = 0 ] || die "some deletes failed; fix the cause and rerun: bash scripts/cost-load.sh cleanup $dir"

  local list
  list=$(awk '{printf "%s'\''%s'\''", (NR>1?",":""), $1}' "$dir/orgs.txt")
  local left
  # A failed upload leaves an upload row with no incident, which the API does
  # not list, and may leave its bundle in the bucket. everything under a
  # throwaway org's prefix belongs to this run, so remove it directly; the org
  # delete below then removes the rows by cascade.
  left=$(q "SELECT count(*) FROM uploads WHERE organization_id IN ($list)")
  if [ "$left" != 0 ]; then
    echo "$left upload row(s) without a listed incident (failed uploads); removing their objects and rows"
    if [ "$HAVE_AWS" = 1 ]; then
      while read -r id name cfg; do
        s3 rm --recursive --quiet "s3://$BUCKET/orgs/$id/" </dev/null || die "could not clear orgs/$id/ in the bucket"
      done < "$dir/orgs.txt"
    else
      echo "NOTE: aws CLI not available; delete these keys by hand if they exist:"
      q "SELECT object_key FROM uploads WHERE organization_id IN ($list)"
    fi
  fi
  q "DELETE FROM organizations WHERE id IN ($list) AND name LIKE '$run-%'" >/dev/null
  left=$(q "SELECT count(*) FROM organizations WHERE id IN ($list)")
  [ "$left" = 0 ] || die "$left organization row(s) remain"
  # sweep any org carrying this run's name that the list missed (a run stopped
  # by an older version of this script between creating an org and recording
  # it). the run name is unique to the run, so nothing else can match.
  local stray
  stray=$(q "SELECT id FROM organizations WHERE name LIKE '$run-%'")
  for id in $stray; do
    case "$id" in org_*) ;; *) die "unexpected org id '$id'" ;; esac
    if [ "$HAVE_AWS" = 1 ]; then
      s3 rm --recursive --quiet "s3://$BUCKET/orgs/$id/" </dev/null || die "could not clear orgs/$id/ in the bucket"
    fi
    q "DELETE FROM organizations WHERE id = '$id' AND name LIKE '$run-%'" >/dev/null
    echo "removed unlisted org $id from this run"
  done
  left=$(q "SELECT count(*) FROM organizations WHERE name LIKE '$run-%'")
  [ "$left" = 0 ] || die "$left organization row(s) named $run-* remain"
  echo "PASS: organizations deleted; tokens, memberships and usage rows removed by cascade"
  if [ "$HAVE_AWS" = 1 ]; then
    local objs=0 n
    while read -r id name cfg; do
      # aws s3 ls exits 1 when nothing matches, which is the expected result
      # here, so an empty listing must count as zero, not end the script.
      n=$( { s3 ls --recursive "s3://$BUCKET/orgs/$id/" </dev/null || true; } | wc -l | tr -d ' ')
      objs=$((objs + n))
    done < "$dir/orgs.txt"
    [ "$objs" = 0 ] || die "$objs object(s) remain under the run's org prefixes"
    echo "PASS: no objects left under the run's org prefixes"
  else
    echo "NOTE: aws CLI not available; bucket not checked"
  fi
  rm -f "$dir"/org-*.json "$dir"/org-*.json.hdr
  echo "PASS: token files removed. Measurements are kept in $dir"
}

if [ "$MODE" = cleanup ]; then
  [ $# -ge 2 ] || die "usage: bash scripts/cost-load.sh cleanup DIR"
  cleanup "$2"
  exit 0
fi
[ "$MODE" = run ] || die "unknown mode '$MODE' (use: run, or cleanup DIR)"

# ------------------------------------------------------------------- load run
RUN="costload-$(date -u +%m%d%H%M)"
OUT=${OUT:-"/tmp/runopsy-cost-load-$(date -u +%Y%m%dT%H%M%SZ)"}
mkdir -p "$OUT"
chmod 700 "$OUT"
echo "$RUN" > "$OUT/run.txt"
: > "$OUT/orgs.txt"
: > "$OUT/uploads.tsv"
printf 'stage\tincidents\tuploads_ok\tuploads_failed\tstage_seconds\tmedian_upload_s\tdb_bytes\tbucket_objects\tbucket_bytes\trailway_usage\tneon_usage\n' > "$OUT/stages.tsv"

FIX=()
for f in "$FIXTURES_DIR"/*.runopsy; do FIX+=("$f"); done
NFIX=${#FIX[@]}
[ "$NFIX" -ge 1 ] || die "no bundles in $FIXTURES_DIR"
MAX=0
for s in $STAGES; do [ "$s" -gt "$MAX" ] && MAX=$s; done
NORGS=$(( (MAX + NFIX - 1) / NFIX ))

code=$(curl -sS -o /dev/null -w '%{http_code}' "$API/healthz" || echo 000)
case "$code" in 200|404) ;; *) die "API at $API is not answering (status $code)" ;; esac

cat <<EOF

7.59 cost load against $API
  run name:     $RUN
  stages:       $STAGES incidents
  bundles:      $NFIX fixtures from $FIXTURES_DIR, one copy per org
  orgs:         up to $NORGS throwaway orgs named $RUN-NN
  output:       $OUT
Nothing in your own organization is touched. Clean up afterwards with:
  bash scripts/cost-load.sh cleanup $OUT
EOF
printf 'Type LOAD to start, anything else to stop: '
read -r answer
[ "$answer" = LOAD ] || die "stopped before loading"

ORG_IDS=()
ORG_CFGS=()
new_org() {
  local n=$1 id name cfg tok
  id="org_$(openssl rand -hex 16)"
  name=$(printf '%s-%02d' "$RUN" "$n")
  cfg="$OUT/org-$(printf '%02d' "$n").json"
  # record the org before anything can fail, so cleanup always finds it.
  echo "$id $name $cfg" >> "$OUT/orgs.txt"
  # A brief network drop between this machine and neon must not end a long
  # run, so each step is retried a few times.
  local try
  for try in 1 2 3 4; do
    q "INSERT INTO organizations (id, name) VALUES ('$id', '$name') ON CONFLICT (id) DO NOTHING" >/dev/null && break
    [ "$try" = 4 ] && die "could not create org $name (database unreachable); run cleanup"
    echo "  database unreachable creating $name; retrying in $((try * 10))s"
    sleep $((try * 10))
  done
  for try in 1 2 3 4; do
    tok=$(bin/runopsy-cloud token -database "$DSN" -user "$RUN" -org "$id" -role owner -description "7.59 cost load $RUN") && break
    [ "$try" = 4 ] && die "could not create a token for $name (database unreachable); run cleanup"
    echo "  database unreachable creating a token for $name; retrying in $((try * 10))s"
    sleep $((try * 10))
  done
  ( umask 077; printf '%s' "$tok" | python3 -I -c '
import json, sys
json.dump({"endpoint": sys.argv[1], "token": sys.stdin.read().strip()}, open(sys.argv[2], "w"))' "$API" "$cfg" )
  tok=""
  ORG_IDS+=("$id")
  ORG_CFGS+=("$cfg")
}

measure() {
  local stage=$1 ok=$2 failed=$3 secs=$4 med db objs="-" bytes="-" rw nn
  med=$(python3 -I - "$OUT/uploads.tsv" "$stage" <<'PY'
import statistics, sys
xs = [float(l.split("\t")[3]) for l in open(sys.argv[1]) if l.split("\t")[0] == sys.argv[2]]
print(f"{statistics.median(xs):.3f}" if xs else "-")
PY
)
  db=$(q "SELECT pg_database_size(current_database())")
  if [ "$HAVE_AWS" = 1 ]; then
    read -r objs bytes < <(s3 ls --recursive --summarize "s3://$BUCKET/" </dev/null \
      | awk '/Total Objects:/{o=$3} /Total Size:/{s=$3} END{print o+0, s+0}')
  fi
  echo
  echo "Stage $stage incidents: $ok uploaded, $failed failed, ${secs}s, median upload ${med}s"
  echo "  database ${db} B; bucket ${objs} objects, ${bytes} B"
  echo "Now read the usage pages (they can lag a few minutes):"
  echo "  Railway: workspace -> Usage, current cycle total and per service"
  echo "  Neon:    project -> Monitoring / Billing (compute hours, storage)"
  printf '  Railway usage so far this cycle (e.g. "\$0.42 api 0.31 web 0.11"; Enter to skip): '
  read -r rw
  printf '  Neon usage (e.g. "0.3 CU-h, 31 MB"; Enter to skip): '
  read -r nn
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage" "$stage" "$ok" "$failed" "$secs" "$med" "$db" "$objs" "$bytes" "${rw:--}" "${nn:--}" >> "$OUT/stages.tsv"
}

echo
echo "Baseline before loading:"
measure 0 0 0 0

k=0
TOTAL_FAILED=0
for stage in $STAGES; do
  t0=$(now)
  ok=0
  failed=0
  while [ "$k" -lt "$stage" ]; do
    o=$((k / NFIX))
    [ "$o" -lt "${#ORG_IDS[@]}" ] || new_org $((o + 1))
    bundle=${FIX[$((k % NFIX))]}
    u0=$(now)
    if bin/runopsy-agent upload -config "${ORG_CFGS[$o]}" "$bundle" </dev/null >> "$OUT/upload.log" 2>&1; then
      res=ok
      ok=$((ok + 1))
    else
      res=failed
      failed=$((failed + 1))
      TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    u1=$(now)
    printf '%s\t%s\t%s\t%s\t%s\n' "$stage" "$k" "$(basename "$bundle")" \
      "$(python3 -I -c 'import sys; print(f"{float(sys.argv[2])-float(sys.argv[1]):.3f}")' "$u0" "$u1")" "$res" >> "$OUT/uploads.tsv"
    k=$((k + 1))
    [ $((k % 50)) = 0 ] && echo "  $k uploaded ($TOTAL_FAILED failed so far)"
    [ "$TOTAL_FAILED" -le 20 ] || die "more than 20 uploads failed; see $OUT/upload.log, then run cleanup"
  done
  t1=$(now)
  measure "$stage" "$ok" "$failed" "$(python3 -I -c 'import sys; print(round(float(sys.argv[2])-float(sys.argv[1])))' "$t0" "$t1")"
done

python3 -I - "$OUT/stages.tsv" > "$OUT/summary.md" <<'PY'
import sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1])][1:]
print("| Incidents | Uploads ok / failed | Stage time | Median upload | Database | Bucket objects | Bucket bytes | Railway usage | Neon usage |")
print("|---:|---:|---:|---:|---:|---:|---:|---|---|")
for r in rows:
    stage, _, ok, failed, secs, med, db, objs, size, rw, nn = r
    print(f"| {stage} | {ok} / {failed} | {secs} s | {med} s | {db} B | {objs} | {size} | {rw} | {nn} |")
PY
echo
echo "Load finished. Measurements: $OUT/summary.md"
cat "$OUT/summary.md"
echo
printf 'Type CLEANUP to delete the run now (or anything else to keep it for later): '
read -r answer
if [ "$answer" = CLEANUP ]; then
  cleanup "$OUT"
else
  echo "Kept. Clean up later with: bash scripts/cost-load.sh cleanup $OUT"
fi
