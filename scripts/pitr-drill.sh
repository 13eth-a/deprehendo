#!/usr/bin/env bash
# Point-in-time recovery rehearsal (checklist 7.56), runnable without a cloud
# account.
#
# what it proves, end to end:
#   1. a base backup plus archived WAL restores the cloud database to a chosen
#      timestamp, and *only* to that timestamp;
#   2. the object store is a second backup domain (restoring the database
#      without it leaves rows that list but 404 on analysis and bundle) so the
#      drill snapshots it at the same logical time and restores the pair;
#   3. the restored pair serves the pre-loss incident byte for byte and the
#      post-target upload is absent.
#
# the mechanics are the same ones a managed provider runs for restore-to-
# timestamp (base backup + continuous WAL + recovery target). replace the
# container's postgres with the provider's console/CLI in the managed version;
# see docs/cloud/pitr-drill.md.
#
# requires: docker, and bin/runopsy-cloud, bin/runopsy-agent,
# bin/runopsy-analyzer (`make build`). KEEP=1 keeps the container and volume.
#
# usage: scripts/pitr-drill.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

CT=${PITR_CONTAINER:-runopsy-pitr}
VOL=${PITR_VOLUME:-runopsy-pitr-work}
PORT_PRIMARY=55440
PORT_RESTORED=55441
ADDR_LIVE=127.0.0.1:56210
ADDR_RESTORED=127.0.0.1:56211
KEEP=${KEEP:-0}

fail() { echo "PITR-DRILL-FAIL: $*" >&2; exit 1; }
for bin in runopsy-cloud runopsy-agent runopsy-analyzer; do
  [ -x "bin/$bin" ] || fail "missing bin/$bin; run make build first"
done
command -v docker >/dev/null 2>&1 || fail "docker is required"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/runopsy-pitr.XXXXXX")
LIVE_STORE=$WORK/storage-live
SNAP_STORE=$WORK/storage-snapshot
mkdir -p "$LIVE_STORE" "$SNAP_STORE"

SERVE_PID=""
cleanup() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  if [ "$KEEP" != "1" ]; then
    docker rm -f "$CT" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

DSN="postgres://postgres@127.0.0.1:$PORT_PRIMARY/runopsy?sslmode=disable"
RDSN="postgres://postgres@127.0.0.1:$PORT_RESTORED/runopsy?sslmode=disable"

docker rm -f "$CT" >/dev/null 2>&1 || true
docker volume rm "$VOL" >/dev/null 2>&1 || true
docker volume create "$VOL" >/dev/null
docker run -d --name "$CT" -v "$VOL:/work" \
  -p "$PORT_PRIMARY:5432" -p "$PORT_RESTORED:5433" \
  postgres:16-alpine sleep infinity >/dev/null
docker exec -u root "$CT" chown -R postgres:postgres /work

cat >"$WORK/inside.sh" <<'INSIDE'
#!/usr/bin/env bash
# Container-side half: initdb, WAL archiving, base backup, restore.
set -euo pipefail
command -v pg_ctl >/dev/null 2>&1 || { echo "pg_ctl is not in the image" >&2; exit 1; }
DATA=/work/primary
BASE=/work/base
RESTORED=/work/restored
WAL=/work/wal

case "${1:-}" in
init)
  rm -rf "$DATA" "$BASE" "$RESTORED" "$WAL"
  mkdir -p "$WAL" "$BASE" "$RESTORED"
  initdb -D "$DATA" -U postgres --auth=trust >/work/initdb.log 2>&1
  # Docker publishes the port through the bridge: accept the gateway's source
  # address, and listen on all interfaces inside the container.
  echo "host all all 0.0.0.0/0 trust" >>"$DATA/pg_hba.conf"
  cat >>"$DATA/postgresql.conf" <<CONF
wal_level = replica
archive_mode = on
archive_command = 'test ! -f /work/wal/%f && cp %p /work/wal/%f'
max_wal_senders = 4
listen_addresses = '*'
port = 5432
unix_socket_directories = '/tmp'
CONF
  pg_ctl -D "$DATA" -l /work/primary.log -w start >/dev/null
  createdb -h 127.0.0.1 -U postgres runopsy
  pg_basebackup -h 127.0.0.1 -U postgres -D "$BASE" -c fast -X stream >/work/basebackup.log 2>&1
  echo "base backup taken"
  ;;
checkpoint)
  psql -h 127.0.0.1 -U postgres -d runopsy -Atc "CHECKPOINT" >/dev/null
  psql -h 127.0.0.1 -U postgres -d runopsy -Atc "SELECT pg_switch_wal()" >/dev/null
  echo "wal segments archived: $(find "$WAL" -type f | wc -l | tr -d ' ')"
  ;;
stop)
  pg_ctl -D "$DATA" -m fast -w stop >/dev/null
  echo "primary stopped"
  ;;
restore)
  target=${2:?restore needs a timestamp}
  rm -rf "$RESTORED"
  cp -a "$BASE" "$RESTORED"
  # pg_basebackup fills a directory the drill created; Postgres refuses to
  # start a data directory that is group/world accessible.
  chmod 700 "$RESTORED"
  cat >>"$RESTORED/postgresql.conf" <<CONF
restore_command = 'cp /work/wal/%f %p'
recovery_target_time = '$target'
recovery_target_action = 'promote'
CONF
  touch "$RESTORED/recovery.signal"
  # No -w: a recovering server is not ready yet, and its log has the reason if
  # it refuses to start at all.
  pg_ctl -D "$RESTORED" -l /work/restored.log start -o "-p 5433 -k /tmp" >/dev/null || {
    echo "restored server did not start" >&2
    tail -40 /work/restored.log >&2
    exit 1
  }
  state=t
  for _ in $(seq 1 120); do
    state=$(psql -h 127.0.0.1 -p 5433 -U postgres -d runopsy -Atc "SELECT pg_is_in_recovery()" 2>/dev/null || echo t)
    [ "$state" = "f" ] && break
    sleep 0.25
  done
  [ "$state" = "f" ] || { echo "recovery did not complete" >&2; tail -20 /work/restored.log >&2; exit 1; }
  echo "recovered to $target and promoted"
  ;;
*)
  echo "usage: inside.sh init|checkpoint|stop|restore <timestamp>" >&2
  exit 2
  ;;
esac
INSIDE
docker cp "$WORK/inside.sh" "$CT:/work/inside.sh" >/dev/null

echo "== 1. primary with WAL archiving and a base backup =="
docker exec -u postgres "$CT" bash /work/inside.sh init

wait_http() {
  local addr=$1
  for _ in $(seq 1 150); do
    if curl -s -o /dev/null "http://$addr/api/incidents"; then return 0; fi
    sleep 0.1
  done
  return 1
}

echo "== 2. migrate, seed an organization and upload the pre-loss incident =="
./bin/runopsy-cloud migrate -database "$DSN"
docker exec "$CT" psql -h 127.0.0.1 -U postgres -d runopsy -Atc \
  "INSERT INTO organizations (id,name) VALUES ('org_pitr01','PITR Drill')" >/dev/null
TOKEN=$(./bin/runopsy-cloud token -database "$DSN" -user pitr-user -org org_pitr01 -description pitr)
./bin/runopsy-cloud serve -database "$DSN" -addr "$ADDR_LIVE" \
  -storage-root "$LIVE_STORE" -analyzer "$ROOT/bin/runopsy-analyzer" -stats-interval 0 \
  >"$WORK/serve-live.log" 2>&1 &
SERVE_PID=$!
wait_http "$ADDR_LIVE" || fail "live server did not start"
printf '{"endpoint":"http://%s","token":"%s"}\n' "$ADDR_LIVE" "$TOKEN" >"$WORK/config.json"
chmod 600 "$WORK/config.json"
./bin/runopsy-agent upload -config "$WORK/config.json" testdata/incidents/frozen-worker.runopsy >/dev/null
./bin/runopsy-agent analyze --document "$WORK/local.json" testdata/incidents/frozen-worker.runopsy >/dev/null
INCIDENT_ONE=$(docker exec "$CT" psql -h 127.0.0.1 -U postgres -d runopsy -Atc \
  "SELECT external_incident_id FROM incidents")
[ -n "$INCIDENT_ONE" ] || fail "the first upload produced no incident row"

echo "== 3. mark the recovery point, snapshot objects, then commit past it =="
TARGET=$(docker exec "$CT" psql -h 127.0.0.1 -U postgres -d runopsy -Atc "SELECT clock_timestamp()")
docker exec -u postgres "$CT" bash /work/inside.sh checkpoint
cp -R "$LIVE_STORE"/. "$SNAP_STORE"/
# enough separation that the two commits cannot share a timestamp.
sleep 2
./bin/runopsy-agent upload -config "$WORK/config.json" testdata/incidents/process-group-kill.runopsy >/dev/null
INCIDENT_TWO=$(docker exec "$CT" psql -h 127.0.0.1 -U postgres -d runopsy -Atc \
  "SELECT external_incident_id FROM incidents WHERE external_incident_id <> '$INCIDENT_ONE'")
[ -n "$INCIDENT_TWO" ] || fail "the second upload produced no incident row"
echo "   recovery target: $TARGET"
echo "   before target: $INCIDENT_ONE (should survive)"
echo "   after  target: $INCIDENT_TWO (should be gone)"
echo "   sql rows before loss: $(docker exec "$CT" psql -h 127.0.0.1 -U postgres -d runopsy -Atc "SELECT count(*) FROM incidents")"
docker exec -u postgres "$CT" bash /work/inside.sh checkpoint
kill "$SERVE_PID"; wait "$SERVE_PID" 2>/dev/null || true; SERVE_PID=""

echo "== 4. lose the primary and restore to the timestamp =="
docker exec -u postgres "$CT" bash /work/inside.sh stop
docker exec -u postgres "$CT" bash /work/inside.sh restore "$TARGET"

RESTORED_INCIDENTS=$(docker exec "$CT" psql -h 127.0.0.1 -p 5433 -U postgres -d runopsy -Atc \
  "SELECT count(*) FROM incidents")
RESTORED_ID=$(docker exec "$CT" psql -h 127.0.0.1 -p 5433 -U postgres -d runopsy -Atc \
  "SELECT external_incident_id FROM incidents")
LOST_PRESENT=$(docker exec "$CT" psql -h 127.0.0.1 -p 5433 -U postgres -d runopsy -Atc \
  "SELECT count(*) FROM incidents WHERE external_incident_id = '$INCIDENT_TWO'")
echo "   restored incidents: $RESTORED_INCIDENTS (want 1)"
echo "   restored id: $RESTORED_ID (want $INCIDENT_ONE)"
echo "   post-target rows present: $LOST_PRESENT (want 0)"
[ "$RESTORED_INCIDENTS" = "1" ] || fail "restored database has $RESTORED_INCIDENTS incidents, want 1"
[ "$RESTORED_ID" = "$INCIDENT_ONE" ] || fail "restored incident is $RESTORED_ID, want $INCIDENT_ONE"
[ "$LOST_PRESENT" = "0" ] || fail "a commit after the recovery target survived"
echo "   schema: $(./bin/runopsy-cloud migrate -database "$RDSN")"

echo "== 5. serve the restored pair: database plus object snapshot =="
./bin/runopsy-cloud serve -database "$RDSN" -addr "$ADDR_RESTORED" \
  -storage-root "$SNAP_STORE" -analyzer "$ROOT/bin/runopsy-analyzer" -stats-interval 0 \
  >"$WORK/serve-restored.log" 2>&1 &
SERVE_PID=$!
wait_http "$ADDR_RESTORED" || fail "restored server did not start"
CODE_ANALYSIS=$(curl -s -o "$WORK/analysis.json" -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "http://$ADDR_RESTORED/api/incidents/$INCIDENT_ONE/analysis")
CODE_BUNDLE=$(curl -s -o "$WORK/bundle.runopsy" -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "http://$ADDR_RESTORED/api/incidents/$INCIDENT_ONE/bundle")
CODE_LOST=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "http://$ADDR_RESTORED/api/incidents/$INCIDENT_TWO")
echo "   pre-loss analysis: $CODE_ANALYSIS (want 200); bundle: $CODE_BUNDLE (want 200); post-target incident: $CODE_LOST (want 404)"
[ "$CODE_ANALYSIS" = "200" ] || fail "restored analysis answered $CODE_ANALYSIS"
[ "$CODE_BUNDLE" = "200" ] || fail "restored bundle answered $CODE_BUNDLE"
[ "$CODE_LOST" = "404" ] || fail "post-target incident answered $CODE_LOST, want 404"
cmp "$WORK/analysis.json" "$WORK/local.json" || fail "restored analysis differs from the CLI document"
cmp "$WORK/bundle.runopsy" testdata/incidents/frozen-worker.runopsy || fail "restored bundle differs from the original"
echo "   restored analysis == CLI document; restored bundle == original bytes"

echo "PITR-DRILL-OK: database and object store recovered as a pair to $TARGET"
