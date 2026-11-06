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

## R7-R3 failure and resource evidence (#45)
The required F-live upload probe now observes an actual S3 multipart session before
closing a partial-body TLS connection, stalling a body until the eight-second
transport deadline, or expiring a write grant while its body is incomplete.
Each case checks absence of completed staging objects, unfinished sessions, SQL
part markers and received-byte accounting, then retries the same part index with
a fresh grant and explicitly aborts the reservation. The owned fixture lease is
extended directly for this campaign; that setup does not qualify a renewal API.

On Linux, sample only the runtime PID's resident memory every 10 ms around an
accepted 1-GiB reservation, rejected 1-GiB part declaration and generated 4-MiB
maximum part. Require less than 64 MiB of RSS growth and less than 192 MiB absolute
RSS. Kernel VmHWM and VmPeak additionally catch brief resident/mapped peaks;
virtual peak growth must remain below 128 MiB, including lazy untouched allocations.
These are conservative regression budgets for the pinned debug runtime, not
a production capacity guarantee or an exact allocation counter. Successful maximum
writes and failed streams are followed by private-prefix and multipart cleanup
observations. No whole-artifact client buffer is used.

The harness requires the campaign completion marker as well as the named test's
successful, non-skipped result. Missing campaign evidence fails the gate. This
campaign does not claim process-death incomplete-session cleanup, finalization
crash coverage, or production multi-host resource sizing; ADR-004's backend lifecycle
requirement and M1-PR8's finalization matrix remain applicable.
