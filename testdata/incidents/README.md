# Diagnosis evaluation fixtures

This directory contains `.runopsy` bundles and adjacent ground-truth sidecars
used only by tests and `runopsy-agent evaluate`. A sidecar is named
`<bundle>.runopsy.ground-truth.json`, for example:

```json
{
  "expected_signature": "FROZEN_PROCESS"
}
```

Healthy baselines use:

```json
{
  "healthy": true
}
```

Ground truth is deliberately out of band and must never be added to a normal
incident bundle: it is test metadata, not collected evidence. For healthy cases,
`UNKNOWN` is an acceptable correct prediction and is not counted as a false
positive; a positive diagnosis is a false positive.

Run the evaluator with:

```sh
go run ./cmd/runopsy-agent evaluate ./testdata/incidents
```

Use `--json` for machine-readable cases and confusion matrix. The corpus has
nine single-cause fault fixtures (one per signature) and ten healthy-but-weird
baselines. After the architecture/implementation review, the baseline is 16/19 correct top
diagnoses, 0 healthy false positives and 13 UNKNOWN. OOM, CPU spin and broker
stall retain their original injected-fault labels but are explicit false
negatives: v1 lacks the evidence needed to distinguish them from healthy work.
Calibration must not improve reported accuracy by relabeling these faults. Regenerate all fixtures with:

```sh
RUNOPSY_WRITE_FIXTURES=1 go test ./internal/diagnosis -run TestWriteIncidentCorpus
```

The fixtures and their labels are written by the implementation team, so this
is a regression harness for classification behavior, not independent accuracy
validation. Editing a fixture by hand is pointless: the generator overwrites
it.
