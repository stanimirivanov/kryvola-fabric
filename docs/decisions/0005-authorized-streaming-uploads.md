# ADR-005: Authorize the streaming boundary before private storage

## Status
Proposed with M1-PR7-R2 (#43); restores the planned HTTP staging boundary (D02/D03).

## Date
2026-11-06

## Decision
Use the pinned Spec upload/abort schemas and existing SPIFFE/one-use grant boundary.
Keep part bodies outside the bounded JSON collector. Adapt the existing object_store
multipart implementation through tokio-util StreamReader (MIT; exact 0.7.20 already
transitive in the lock; no new transitive packages). Require positive Content-Length
for parts; HTTP framing defines the body and the adapter checks its actual length.
Chunked bodies without a declared length are rejected, rather than buffered.

Use a fenced store at the HTTP boundary: acquire the registry operation row before
quota/upload rows, validate workflow/attempt/fence, open barriers, selection, lease
and operation deadline, and retain that lock through mutation. Bind the permit to
monotonic transport/provider and PostgreSQL deadlines, plus wall-clock credential
expiry. Persist observed attempt retirement even when rejecting an expired lease.
Trusted internal UploadStore::new callers keep their existing permit-only contract;
they do not constitute a remotely authorized entry point.

Stage canonical manifests at a private write-once key bound to the grant digest.
No readable reference or finalization endpoint is added. Ambiguous storage/SQL
outcomes retain private bytes; abort and existing prefix reclamation own cleanup.

Configure S3 only through a bounded operator-private file, never request metadata.
Return fixed protocol errors; do not log raw credentials, endpoints, tenant or scope.
This opt-in boundary requires both workload authentication and the SQL registry.

## Rollout and rollback
Deploy after R7-R1/R6-R1 with their migrations. Enable via --uploads only after
provisioning the private bucket/config and operator grants. Omitting --uploads or
reverting this slice disables the routes; existing staged data and accounting remain
compatible. No schema migration or contract pin change is needed.

## Evidence and limits
F-live owns a required named real SPIRE/HTTPS/PostgreSQL/S3 probe plus negative
controls against absent/skipped proof. It checks quota races, scope/purpose/fence
denials, a part above the control-body cap, canonical metadata staging and abort.
Extended disconnect, interruption and resource campaigns belong to R7-R3. Backend
incomplete-multipart lifecycle rules from ADR-004 remain necessary after process death.
