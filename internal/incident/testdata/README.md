`v1-minimal.runopsy` is a fixed format-v1/schema-v1/json-v1 compatibility fixture.
It contains one synthetic Linux process sample and an incident-triggered event
at 2026-10-26T12:00:00Z. All identifiers and metrics are synthetic; identifying
strings contain conservative-v1 redaction placeholders. The fixture is decoded
from disk by `TestReadVersionOneGoldenCompatibility`, without regenerating it
with the current encoder. Intentional public format changes should add a new
fixture and compatibility policy rather than silently replacing this file.
