# adversarial Phase 5 pass: adversarial attack suite

**Owner:** adversarial (attacks) · **Ported to the canonical tree and re-run by principal:** 2026-10-31
**Basis:** the Phase 5 plan's adversarial role (adversarial review of every parser,
correlation rule, signature and privacy component; 5.37 primary; final-audit
share with secondary).

Each test tries to make the provider say something the runner did not say, or
let a secret out. The suite is `internal/provider/github/adversarial_attack_test.go`
(`TestAdversarialAttack*`, 11 tests). It was written against an older copy of the
repository. There it found two defects: "Running jobs in parallel" read as job
acceptance, and one record longer than the read budget stalled the log reader
for good. The canonical tree had already fixed both independently (the `\b`
in the acceptance pattern, and dropping a window with no newline). On this
tree all 11 tests pass, and they stay as regression coverage.

| Area | Attack | Result on the canonical tree |
|---|---|---|
| 5.7 log reader | "Running jobs …" / "Running jobsite …" as acceptance | Held |
| 5.7 log reader | record longer than the read budget | Held |
| 5.7 log reader | worker-only intent phrase in a listener log | Held |
| 5.7 log reader | partial trailing record, then completion (reported once) | Held |
| 5.7 log reader | CRLF line endings | Held |
| 5.40 healthy look-alike | negated or unrelated job sentences in a worker log | Held |
| 5.2 discovery / C2 | `Runner.Listener` run from outside an installation | Held: not a supervisor |
| 5.5 correlation / C1 | worker PID reused with a new start time | Held: second incarnation |
| 5.12 / 5.36 privacy | token in `agentName`, both privacy levels | Held: withheld |
| 5.12 / 5.36 privacy | token and `?sig=` in `workFolder`, both levels | Held: nothing reaches the bundle |
| 5.37 API failures | GitHub outage (503), network unreachable | Held: degraded health, valid section, no credential leak |

With the existing API tests (401, 403, 429, 500), all five 5.37 failure modes
are covered.

## adversarial items not done

These review rows from the plan were not attacked in this pass: 5.11 (now
including `--repo` location), 5.13–5.15, 5.27–5.30, 5.33 (see audit F2),
5.39–5.41 fixture fidelity, and 5.50 documentation. The healthy look-alikes
for 5.20–5.24 are now possible, since the signatures exist; the principal B1 review
added the S1 boundary cases (`signatures_s1_test.go`).
