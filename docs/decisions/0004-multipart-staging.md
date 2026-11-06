# ADR-004: Publish unique private multipart writes through SQL

## Status
Proposed with M1-PR7-R1 (#41); restores the planned object_store adapter (D16).

## Date
2026-11-06

## Decision
Use the existing pinned object_store 0.14.2 MultipartUpload interface. Each
application chunk fits the final-part exception to S3's minimum non-final part
size. Keep one fixed 4-MiB buffer and bounded reads; do not accumulate a whole
artifact or implement a separate multipart wire protocol. The primitive trait
keeps ownership of the handle through completion errors so explicit abort remains
possible; a consuming convenience writer cannot provide that ownership boundary. The exact async-trait
0.1.92 dev dependency is already in the lock (MIT/Apache-2.0); no runtime package
is added.

The SDK completes with overwrite semantics. Publish a random private attempt key
through the existing locked SQL part marker, rather than overwriting a canonical
staging key or relying on a non-atomic HEAD check. A nullable additive mapping
retains legacy reads. Finalized artifact identities and immutable paths do not change.

Own abort/delete cleanup across errors and cancellation through SQL preparation.
Retain completed bytes at commit admission because its acknowledgement can be
lost. Completed orphans remain private and use existing prefix reclamation;
incomplete sessions require backend lifecycle rules after process/runtime death,
failed cleanup, or an ambiguous initiation response. Async Drop cleanup alone
cannot guarantee crash cleanup.

## Rollout and rollback
Quiesce writers before applying migration 0008. New code reads both layouts.
Drain/abort mapped temporary uploads before rolling back. The guarded down
migration intentionally retains the nullable column/data but lets SQLx remove
version 8 from its ledger; old binaries then accept the prior migration set.
Reapply the idempotent up migration before enabling new writers again. Tests
exercise undo/reapply, refusal with live mapped parts, legacy finalization,
write-once accounting and no leftover real multipart sessions.
