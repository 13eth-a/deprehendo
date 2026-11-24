# Test fixtures: analysis documents

`analysis/*.json` holds 19 real `deprehendo.analysis` version 1 documents, one per
bundle in `testdata/incidents/*.deprehendo`. They are the input to
`test/fixtures.test.ts` and the render tests.

## Provenance

- Each file is the output of `analysis.Run(bundle, sha256hex, Options)`
  followed by `analysis.WriteJSON`, run on the Mac repository's Go tree.
- Output is deterministic: the same bundle gives byte-identical JSON.
- The file name is the bundle name without `.deprehendo`.
- The CLI's diagnosis and the document's diagnosis agree on all 19 bundles,
  after the documented enrichment.

## Regenerating

1. Generate each document with the Go analyzer on the same tree.
2. Overwrite the files in `analysis/`.
3. Regenerate `analysis-keys.golden.json` with the same key-shape walk that
   `test/fixtures.test.ts` uses (`shapeOf`), and update it in the same change.
4. Run `npm test`.

The current `analyze` command has no `--document` flag. Generation uses a small
generator that calls `analysis.Run` and `WriteJSON` directly. That generator is
not in this repository yet. Until `analyze --document` exists, regeneration is
not reproducible from the repo alone.

## Golden file

`analysis-keys.golden.json` maps each object path (for example `$.causal.edges[]`)
to its `key:type` pairs across all 19 fixtures. A Go change to the document
shape fails `the key shape of every fixture matches the golden file` until the
types and the golden are updated together.
