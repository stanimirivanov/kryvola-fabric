# Bounded control descriptors (M0-PR14)

This repository adopts spec `0.1.0-preview.10` at immutable commit
`1a5b57a590487ba116913050af8041f5e5f1fb52` (merged M0-PR13). `spec.lock.json`
pins both complete generated and native artifact manifests. The architecture gate
verifies every file, rejects unlisted files, correlates the native manifest's
generated-source hashes with the generated bundle, and verifies the three private
Python wheel assets. Artifacts are copied unchanged from that commit, never imported
from sibling implementation source or regenerated here. They remain preview contracts.

Construct a Rust `ControlValidator` once and reuse its `decode(kind, bytes, temporal)` method;
`kryvola_fabric.control.decode_control(kind, payload, temporal=False)` is the Python equivalent. They
validate actual Protobuf bytes against the pinned native descriptor set and closed
schemas before a permissive typed decoder or transport. Supported names are exactly
the schema keys in `contracts/native/schemas.json`. Unknown types/versions, missing
required values, nested unknown fields (including undeclared inline key/blob fields),
invalid decimal/artifact/list bounds, duplicate capability/operator entries, and
contradictory operation/execution/reference/status metadata fail closed. Message
parse errors are converted to fixed safe codes with no original cause or diagnostic.
Python raises outside the library exception handler, so even exception context does
not retain rejected values. Rust errors have no source chain.

This is **BEHAVIOR-ADJACENT**, additive strict validation. The existing Rust
`check_control_size` API remains available with its original behavior; checking size
alone still does not validate content. Control payloads are bounded at 64 KiB before
decoding. Temporal payloads are bounded at 32 KiB, and `temporal_call` includes all
payload bytes plus explicitly supplied application headers/framing in its 128 KiB
aggregate budget. Transport adapters must supply the complete uncompressed event
record to the size helper as well as validate its Protobuf payload: these functions
do not parse Redpanda/Temporal SDK envelopes or install SDK hooks.

The returned JSON/dict is a caller-owned metadata snapshot, not a grant or proof.
There is no capability negotiation, wall-clock deadline/revocation/lease check,
registry lookup, signature/proof verification, ciphertext decoder or authorization.
Protobuf's standard merging/order/duplicate-known-field semantics apply; Protobuf
bytes are not canonical signing input. Closed fields cannot detect a secret placed
inside an otherwise valid identifier. Owner custody and transport enforcement still
need their separate implementation/qualification gates.

Prior art: adapt the pinned spec native conformance pattern using
[prost-reflect](https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.DynamicMessage.html)
and Python Protobuf reflection, plus the same generated-schema validators. This adds
exact runtime dependencies and small boundary wrappers, avoiding a handwritten wire
parser or schema fork. Rust pins Prost 0.14.4 (Apache-2.0), prost-reflect 0.16.5 and
serde_json 1.0.154 (MIT/Apache-2.0), and jsonschema 0.60.1 (MIT; default features
disabled, no HTTP/file retrieval enabled). Python pins protobuf 7.35.1
([BSD-3-Clause](https://github.com/protocolbuffers/protobuf/blob/main/LICENSE)) and
jsonschema 4.26.0 ([MIT](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING)).
Rust locks 91 registry packages including the test-only hex adapter; Python adds
six runtime packages with hashes. This increases compile/runtime dependency weight;
full legal/security release disposition remains separate from these license labels.

`uv run --locked python tools/verify.py full` remains the CI gate, including Rust
fmt/Clippy/tests, Python format/lint/types/architecture/tests and wheel build. It now
also probes the built wheel from an isolated working directory and checks its assets.
Local checks are limited to Python checks/tests, provenance and rustfmt per user
instruction; Rust compilation and the full build gate run on CI. Shared golden
vectors cover 20 cases, including 64 KiB control payloads; a derived valid 32 KiB
Temporal fixture pads only bounded reference IDs from the pinned fixtures. Negative
controls cover malformed versions/fields/bytes, unsafe inline fields, context
correlations, aggregate framing overhead, sanitized errors and tampered/mixed assets.
