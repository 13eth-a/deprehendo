GO ?= go
BIN_DIR ?= bin
DEPREHENDO := $(BIN_DIR)/deprehendo-agent
SIM := $(BIN_DIR)/deprehendo-sim
TRACE_RUST := $(BIN_DIR)/deprehendo-trace
CLOUD := $(BIN_DIR)/deprehendo-cloud
ANALYZER := $(BIN_DIR)/deprehendo-analyzer
COST := $(BIN_DIR)/deprehendo-cost

.PHONY: all build test race vet fmt lint clean \
	sim-normal sim-cpu sim-memory sim-freeze sim-orphan \
	sim-tree sim-socket sim-exit sim-signal acceptance \
	trace-build trace-test trace-clippy trace-fmt trace-fixtures \
	trace-bench trace-churn trace-churn-live trace-live \
	test-cloud pitr-drill cost-model force-run

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(DEPREHENDO) ./cmd/deprehendo-agent
	$(GO) build -o $(SIM) ./cmd/deprehendo-sim
	$(GO) build -o $(CLOUD) ./cmd/deprehendo-cloud
	$(GO) build -o $(ANALYZER) ./cmd/deprehendo-analyzer
	$(GO) build -o $(COST) ./cmd/deprehendo-cost
test:
	$(GO) test ./...

acceptance:
	$(GO) test -count=1 ./tests

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# full check: the same set CI runs.
lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -race ./...

sim-normal: build
	$(SIM) normal

sim-cpu: build
	$(SIM) cpu-spin --workers 4 --duration 10s

sim-memory: build
	$(SIM) memory-pressure --rate 16MB --interval 1s --limit 256MB

sim-freeze: build
	$(SIM) frozen-worker

sim-orphan: build
	$(SIM) orphan-process

sim-tree: build
	$(SIM) process-tree

sim-socket: build
	$(SIM) socket-stall

sim-exit: build
	$(SIM) exit --code 137 --hold 1s

sim-signal: build
	$(SIM) signal --signal TERM

# --- rust tracer (phase 6, Linux-only) -------------------------------------

# builds the tracer into $(BIN_DIR) so the manager's sibling-binary resolution
# finds it; all other trace targets depend on this.
trace-build:
	cargo build --manifest-path trace-rs/Cargo.toml --target-dir trace-rs/target
	@mkdir -p $(BIN_DIR)
	cp trace-rs/target/debug/deprehendo-trace $(TRACE_RUST)

trace-test: trace-build
	cargo test --all-targets --manifest-path trace-rs/Cargo.toml

# the same checks rust CI runs.
trace-clippy:
	cargo clippy --all-targets --manifest-path trace-rs/Cargo.toml -- -D warnings

trace-fmt:
	cargo fmt --all --manifest-path trace-rs/Cargo.toml -- --check

# regenerate testdata/trace fixtures with the production rust encoder, then
# prove the go side still decodes them (the 6.56 compatibility check).
trace-fixtures: trace-build trace-test
	$(TRACE_RUST) genfixtures testdata/trace
	mkdir -p $(BIN_DIR)
	$(GO) run ./cmd/deprehendo-agent trace replay testdata/trace/dropped-events.bin > /dev/null

# performance budget (6.49/6.50) and the default churn size (6.51). the go
# bridge tests need no kernel; trace-live adds the real tracer measurement.
trace-bench: trace-build
	$(GO) test -count=1 -run 'TestPipelineChurn' -v ./internal/trace
	$(GO) test -run '^$$' -bench . -benchmem ./internal/trace

trace-churn:
	DEPREHENDO_TRACE_CHURN=100000 $(GO) test -count=1 -run 'TestPipelineChurn' -v ./internal/trace

# the live 100k process run from contract §14: the real tracer, the real
# kernel, as whatever user invokes it (the point is a non-root user with stock
# net.core.rmem_max, where overruns become visible gaps). reports coverage and
# accounted loss rather than asserting the environment was friendly.
trace-churn-live: trace-build
	DEPREHENDO_TRACE_BINARY=$(abspath $(TRACE_RUST)) DEPREHENDO_LIVE_CHURN=100000 \
		$(GO) test -count=1 -timeout 20m -run 'TestLiveChurn' -v ./internal/trace

# live measurements are Linux-only and skip with a reason elsewhere (6.37).
trace-live: trace-build
	DEPREHENDO_TRACE_BINARY=$(abspath $(TRACE_RUST)) $(GO) test -count=1 -run 'TestLive' -v ./internal/trace

# --- cloud backend (phase 7) ------------------------------------------------

# the gated server integration against a real postgres: migrations applied
# through the real runner (twice, proving idempotence), the 7.36 org matrix,
# dedupe, hostile storage refusal, the CLI upload path, the §5.5 upload corpus
# through the worker, the failure combinations (storage/DB/analyzer) and the
# local/cloud document equality check.
# requires docker. skipped cleanly elsewhere: the tests skip without
# DEPREHENDO_CLOUD_TEST_DSN.
#
# the host port is deliberately not 5432: developers commonly run a local
# postgres there, and a silent collision would point the tests at that server
# (where the connecting role may not exist) instead of this container.
CLOUD_TEST_PORT ?= 55432
test-cloud: build force-run
	docker rm -f deprehendo-pg-test >/dev/null 2>&1 || true
	docker run -d --rm --name deprehendo-pg-test \
		-e POSTGRES_PASSWORD=deprehendo -e POSTGRES_DB=deprehendo \
		-p $(CLOUD_TEST_PORT):5432 postgres:16-alpine >/dev/null
	@# -h 127.0.0.1 matters: plain pg_isready talks to the unix socket, which
	@# the initdb temporary server also answers, so it reports ready while the
	@# real server is still starting up and the first migration gets 57P03.
	@for i in $$(seq 1 60); do \
		docker exec deprehendo-pg-test pg_isready -h 127.0.0.1 -U postgres -d deprehendo >/dev/null 2>&1 && break; sleep 1; done; \
	docker exec deprehendo-pg-test pg_isready -h 127.0.0.1 -U postgres -d deprehendo >/dev/null 2>&1 || { \
		echo "postgres container did not become ready"; docker logs deprehendo-pg-test 2>&1 | tail -20; \
		docker rm -f deprehendo-pg-test >/dev/null 2>&1; exit 1; }
	@DSN='postgres://postgres:deprehendo@127.0.0.1:$(CLOUD_TEST_PORT)/deprehendo?sslmode=disable'; \
	if ! ($(CLOUD) migrate -database "$$DSN" && $(CLOUD) migrate -database "$$DSN" && \
		DEPREHENDO_CLOUD_TEST_DSN="$$DSN" $(GO) test -count=1 -run 'TestPhase7' ./tests); then \
		status=1; else \
		status=0; fi; \
	docker rm -f deprehendo-pg-test >/dev/null 2>&1 || true; exit $$status

# Point-in-time recovery rehearsal (7.56): a base backup plus archived WAL,
# restored to a chosen timestamp, with the object store snapshotted and
# restored as a pair. runs against a throwaway postgres container, so it needs
# docker but no provider account. the managed runbook is
# docs/cloud/pitr-drill.md.
pitr-drill: build
	./scripts/pitr-drill.sh

# cloud cost model (7.59): real bundles, the real analyzer child, and, when a
# DSN is given, real row sizes. prices are flags; see the target's output or
# docs/cloud/cost-measurement.md.
COST_DSN ?=
cost-model: build
	$(COST) -runs 5 $(if $(COST_DSN),-database "$(COST_DSN)")

# force-run exists only to defeat make's file-target caching, whose results
# (nothing to be done) would mislead a cloud test that shares no artifacts.
force-run:
	true

clean:
	rm -rf $(BIN_DIR)
