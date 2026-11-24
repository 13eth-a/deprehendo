#!/usr/bin/env bash
# managed neon point-in-time restore drill (7.56), run against production.
#
# what it does, in order:
#   1. preflight: tools, credentials, the neon branch, the API
#   2. records every incident (list, analysis, bundle) and the bucket listing
#   3. records a restore target timestamp from the database clock
#   4. uploads a canary incident that must NOT survive the restore
#   5. asks you to type RESTORE, then restores the root branch to the target
#      (neon keeps the pre-restore state as a backup branch)
#   6. measures RTO: restore start -> canary gone and analyses answering 200
#   7. verifies: same incidents as before, canary absent, analysis and bundle
#      byte-identical, schema current
#   8. deletes the canary's objects, which the database restore cannot remove,
#      and checks the bucket is back to its pre-drill listing
#   9. writes a summary to paste into docs/cloud/pitr-drill.md
#
# everything written to the database after the target is rolled back: the
# canary, and any sign-ups, sessions or uploads made during the drill. run it
# when nobody else is using the dashboard. connections drop briefly.
#
# secrets are never printed. the API token is read from the agent's config
# file into a private header file that is removed on exit.
#
# usage (from the repo root, after `make build`):
#   bash scripts/neon-restore-drill.sh
# overrides: NEON_PROJECT_ID, NEON_BRANCH, DEPREHENDO_API, DEPREHENDO_S3_BUCKET,
# CANARY_BUNDLE, DEPREHENDO_CONFIG, OUT.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT=${NEON_PROJECT_ID:-empty-truth-18465894}
BRANCH=${NEON_BRANCH:-production}
API=${DEPREHENDO_API:?set DEPREHENDO_API to your deployed API URL}
BUCKET=${DEPREHENDO_S3_BUCKET:-deprehendo-0uz5hzbri3moxaaaa}
CANARY=${CANARY_BUNDLE:-testdata/incidents/cpu-spin.deprehendo}
CONFIG=${DEPREHENDO_CONFIG:-"$HOME/Library/Application Support/deprehendo/config.json"}
OUT=${OUT:-"/tmp/deprehendo-restore-drill-$(date -u +%Y%m%dT%H%M%SZ)"}

mkdir -p "$OUT"
chmod 700 "$OUT"
HDR="$OUT/.auth-header"
trap 'rm -f "$HDR"' EXIT

log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$OUT/drill.log"; }
die() { log "FAIL: $*"; log "Notes and copies are in $OUT"; exit 1; }
ok() { log "PASS: $*"; }

# ---------------------------------------------------------------- 1. preflight
for c in neon psql curl python3 shasum; do
  command -v "$c" >/dev/null 2>&1 || die "missing command: $c"
done
[ -x bin/deprehendo-agent ] && [ -x bin/deprehendo-cloud ] || die "run 'make build' first (bin/deprehendo-agent, bin/deprehendo-cloud)"
[ -f "$CANARY" ] || die "canary bundle not found: $CANARY"
[ -f .env.local ] || die ".env.local not found in the repo root"
set -a
# shellcheck disable=SC1091
. ./.env.local
set +a
[ -n "${DATABASE_URL_UNPOOLED:-}" ] || die "DATABASE_URL_UNPOOLED is not set in .env.local"
[ -f "$CONFIG" ] || die "agent config not found: $CONFIG (run bin/deprehendo-agent login first)"

umask 077
python3 -I - "$CONFIG" "$HDR" <<'PY' || die "could not read the token from the agent config"
import json, sys
token = json.load(open(sys.argv[1]))["token"]
open(sys.argv[2], "w").write("Authorization: Bearer " + token + "\n")
PY
umask 022

q() { psql "$DATABASE_URL_UNPOOLED" -XqtAc "$1"; }
# api PATH OUTFILE -> prints the HTTP status
api() { curl -sS -o "$2" -w '%{http_code}' -H @"$HDR" "$API$1" || echo 000; }
# ids_of FILE -> sorted incident ids; prints nothing for an error body, so a
# transient failure during polling does not end the script.
ids_of() {
  python3 -I - "$1" <<'PY' | sort
import json, sys
try:
    rows = json.load(open(sys.argv[1]))
    for row in rows if isinstance(rows, list) else []:
        print(row["incident_id"])
except Exception:
    pass
PY
}

HAVE_AWS=0
if command -v aws >/dev/null 2>&1 && [ -f .env.railway ]; then HAVE_AWS=1; fi
# s3 ARGS -> the aws CLI against the railway bucket. .env.local (loaded above)
# carries neon's own storage settings from `neon deploy` (AWS_ENDPOINT_URL_S3,
# AWS_REGION, keys); clear every inherited AWS variable first so the railway
# credentials are never sent to neon's endpoint. .env.railway may set the
# endpoint and region; otherwise railway's defaults apply.
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

log "drill output: $OUT"
log "project=$PROJECT branch=$BRANCH api=$API canary=$CANARY"
neon branches list --project-id "$PROJECT" > "$OUT/branches-before.txt" 2>&1 || die "neon branches list failed (run 'neon auth' first?)"
grep -q "$BRANCH" "$OUT/branches-before.txt" || die "branch $BRANCH not found in project $PROJECT"
ok "neon CLI reaches project $PROJECT and branch $BRANCH exists"
q "SELECT 1" >/dev/null || die "cannot reach the database"
ok "database reachable"

code=$(api /api/me "$OUT/me.json")
[ "$code" = 200 ] || die "GET /api/me answered $code"
ORG=$(python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1]))["organizations"]; print(o[0]["id"] if len(o)==1 else "")' "$OUT/me.json")
[ -n "$ORG" ] || die "the token must belong to exactly one organization"
ok "API reachable; token is for $ORG"
[ "$HAVE_AWS" = 1 ] && ok "aws CLI and .env.railway found: bucket checks enabled" \
  || log "NOTE: aws CLI or .env.railway missing: bucket checks are skipped and canary objects are listed for manual cleanup"

# ------------------------------------------------------- 2. pre-drill evidence
code=$(api "/api/incidents?limit=200" "$OUT/pre-list.json")
[ "$code" = 200 ] || die "GET /api/incidents answered $code"
ids_of "$OUT/pre-list.json" > "$OUT/pre-ids.txt"
PRE_COUNT=$(wc -l < "$OUT/pre-ids.txt" | tr -d ' ')
[ "$PRE_COUNT" -ge 1 ] || die "the organization has no incidents to verify against"
mkdir -p "$OUT/pre" "$OUT/post"
while read -r id; do
  a=$(api "/api/incidents/$id/analysis" "$OUT/pre/$id.analysis.json")
  b=$(api "/api/incidents/$id/bundle" "$OUT/pre/$id.deprehendo")
  [ "$a" = 200 ] && [ "$b" = 200 ] || die "pre-drill $id: analysis $a, bundle $b (expected 200/200)"
done < "$OUT/pre-ids.txt"
ok "recorded $PRE_COUNT incident(s): list, analysis and bundle, all 200"
if [ "$HAVE_AWS" = 1 ]; then
  s3 ls --recursive "s3://$BUCKET/orgs/$ORG/" | awk '{print $4}' | sort > "$OUT/pre-objects.txt" || die "bucket listing failed"
  ok "recorded $(wc -l < "$OUT/pre-objects.txt" | tr -d ' ') bucket object(s) under orgs/$ORG/"
fi

# ----------------------------------------------------------------- 3. target
sleep 2
TARGET=$(q "SELECT to_char(date_trunc('second', clock_timestamp()) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
[ -n "$TARGET" ] || die "could not read the database clock"
log "restore target (UTC, from the database clock): $TARGET"
sleep 5

# ----------------------------------------------------------------- 4. canary
log "uploading canary $CANARY (must not survive the restore)"
bin/deprehendo-agent upload -config "$CONFIG" "$CANARY" > "$OUT/canary-upload.txt" 2>&1 || {
  cat "$OUT/canary-upload.txt"
  die "canary upload failed"
}
CANARY_ID=""
for _ in $(seq 1 30); do
  api "/api/incidents?limit=200" "$OUT/canary-list.json" >/dev/null
  CANARY_ID=$(ids_of "$OUT/canary-list.json" | comm -13 "$OUT/pre-ids.txt" - | head -1)
  [ -n "$CANARY_ID" ] && break
  sleep 1
done
[ -n "$CANARY_ID" ] || die "the canary upload did not appear in the incident list"
api "/api/incidents/$CANARY_ID" "$OUT/canary-detail.json" >/dev/null
CANARY_UPLOAD=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["upload_id"])' "$OUT/canary-detail.json")
CANARY_SHA=$(shasum -a 256 "$CANARY" | awk '{print $1}')
ok "canary is $CANARY_ID (upload $CANARY_UPLOAD)"
for _ in $(seq 1 60); do
  c=$(api "/api/incidents/$CANARY_ID/analysis" "$OUT/canary-analysis.json")
  [ "$c" = 200 ] && break
  sleep 1
done
[ "$c" = 200 ] || die "canary analysis never became ready (last status $c)"
ok "canary analysis is ready, so it exists after the target"

# -------------------------------------------------------- 5. confirm, restore
BACKUP="${BRANCH}_pre_drill_$(date -u +%Y%m%d_%H%M)"
echo
echo "About to restore branch '$BRANCH' of project $PROJECT to $TARGET."
echo "Everything written after that moment is rolled back, including the canary"
echo "and any sign-ups or sessions created since. Connections drop briefly."
echo "The current state is kept as branch '$BACKUP'."
printf 'Type RESTORE to continue, anything else to stop: '
read -r answer
[ "$answer" = RESTORE ] || die "stopped before the restore; the canary $CANARY_ID is still there (delete it from the dashboard)"

START=$(date +%s)
log "restore started"
neon branches restore "$BRANCH" "^self@$TARGET" --preserve-under-name "$BACKUP" --project-id "$PROJECT" 2>&1 | tee "$OUT/restore.txt" \
  || die "neon branches restore failed"

# ------------------------------------------------------------------- 6. RTO
FIRST_PRE=$(head -1 "$OUT/pre-ids.txt")
END=""
for _ in $(seq 1 300); do
  d=$(api "/api/incidents/$CANARY_ID" "$OUT/poll-canary.json")
  a=$(api "/api/incidents/$FIRST_PRE/analysis" "$OUT/poll-pre.json")
  if [ "$d" = 404 ] && [ "$a" = 200 ]; then END=$(date +%s); break; fi
  sleep 2
done
[ -n "$END" ] || die "after 10 minutes the API still did not show the restored state (canary $d, pre-target analysis $a)"
RTO=$((END - START))
ok "restored state served by the API after ${RTO}s (canary 404, pre-target analysis 200)"

# ------------------------------------------------------------------ 7. verify
code=$(api "/api/incidents?limit=200" "$OUT/post-list.json")
[ "$code" = 200 ] || die "post-restore GET /api/incidents answered $code"
ids_of "$OUT/post-list.json" > "$OUT/post-ids.txt"
cmp -s "$OUT/pre-ids.txt" "$OUT/post-ids.txt" || {
  diff "$OUT/pre-ids.txt" "$OUT/post-ids.txt" | tee -a "$OUT/drill.log"
  die "the incident list differs from the pre-drill list"
}
ok "incident list matches the pre-drill list exactly ($PRE_COUNT), canary absent"
while read -r id; do
  a=$(api "/api/incidents/$id/analysis" "$OUT/post/$id.analysis.json")
  b=$(api "/api/incidents/$id/bundle" "$OUT/post/$id.deprehendo")
  [ "$a" = 200 ] && [ "$b" = 200 ] || die "post-restore $id: analysis $a, bundle $b"
  cmp -s "$OUT/pre/$id.analysis.json" "$OUT/post/$id.analysis.json" || die "$id analysis differs after restore"
  cmp -s "$OUT/pre/$id.deprehendo" "$OUT/post/$id.deprehendo" || die "$id bundle differs after restore"
done < "$OUT/pre-ids.txt"
ok "every analysis and bundle is 200 and byte-identical to the pre-drill copy"
MIGRATE=$(bin/deprehendo-cloud migrate -database "$DATABASE_URL_UNPOOLED" 2>&1) || die "migrate failed: $MIGRATE"
echo "$MIGRATE" >> "$OUT/drill.log"
echo "$MIGRATE" | grep -q "schema is current" || die "migrate did not report 'schema is current'"
ok "deprehendo-cloud migrate: schema is current"
REFS=$(q "SELECT count(*) FROM uploads WHERE id = '$CANARY_UPLOAD'")
[ "$REFS" = 0 ] || die "the canary upload row still exists after the restore"
ok "no canary row in the restored database"

# ------------------------------------------------- 8. canary objects cleanup
# the bucket is not part of the database restore. the canary's objects are now
# named by no row; remove them. the bundle key is content-addressed, so it is
# removed only if no pre-drill bundle has the same hash.
SHARED=0
for f in "$OUT"/pre/*.deprehendo; do
  [ "$(shasum -a 256 "$f" | awk '{print $1}')" = "$CANARY_SHA" ] && SHARED=1
done
CANARY_KEYS="$OUT/canary-objects.txt"
: > "$CANARY_KEYS"
[ "$SHARED" = 0 ] && echo "orgs/$ORG/bundles/$CANARY_SHA.deprehendo" >> "$CANARY_KEYS"
if [ "$HAVE_AWS" = 1 ]; then
  s3 ls --recursive "s3://$BUCKET/orgs/$ORG/documents/$CANARY_UPLOAD" | awk '{print $4}' >> "$CANARY_KEYS" || true
  while read -r key; do
    [ -n "$key" ] || continue
    s3 rm "s3://$BUCKET/$key" >/dev/null </dev/null || die "could not delete canary object $key"
    log "deleted canary object $key"
  done < "$CANARY_KEYS"
  s3 ls --recursive "s3://$BUCKET/orgs/$ORG/" | awk '{print $4}' | sort > "$OUT/post-objects.txt"
  cmp -s "$OUT/pre-objects.txt" "$OUT/post-objects.txt" || {
    diff "$OUT/pre-objects.txt" "$OUT/post-objects.txt" | tee -a "$OUT/drill.log"
    die "the bucket listing differs from the pre-drill listing"
  }
  ok "bucket listing matches the pre-drill listing"
  OBJECTS_RESULT="bucket listing matches the pre-drill listing after removing the canary's objects"
else
  log "MANUAL CLEANUP: delete orgs/$ORG/bundles/$CANARY_SHA.deprehendo (unless shared) and orgs/$ORG/documents/$CANARY_UPLOAD*.json"
  OBJECTS_RESULT="not checked (no aws CLI); canary objects listed for manual cleanup"
fi

# ----------------------------------------------------------------- 9. summary
cat > "$OUT/summary.md" <<EOF
Managed restore drill, $(date -u +%Y-%m-%d), project \`$PROJECT\`, branch \`$BRANCH\`:

| Step | Result |
|---|---|
| target (database clock, UTC) | \`$TARGET\` |
| incidents before the target | $PRE_COUNT, analysis and bundle 200 |
| canary after the target | \`$CANARY_ID\` (\`$(basename "$CANARY")\`), analysis ready |
| restore | \`neon branches restore $BRANCH ^self@$TARGET --preserve-under-name $BACKUP\` |
| RTO (restore start to restored state served by the API) | **${RTO}s** |
| incident list after restore | identical to before; canary 404 |
| analysis and bundle after restore | 200, byte-identical to the pre-drill copies |
| \`deprehendo-cloud migrate\` | schema is current |
| object store | $OBJECTS_RESULT |
| backup branch | \`$BACKUP\` (decide: keep or delete) |
EOF
log "ALL CHECKS PASSED"
echo
cat "$OUT/summary.md"
echo
echo "Saved to $OUT/summary.md. Paste the table above into the chat."
