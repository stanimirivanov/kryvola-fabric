# ADR-002: Bound authorization and provider state

## Status
Proposed with M1-PR5-R2 (#37). Completes the freshness/replay-retention portion
left open by ADR-001; the authoritative M1 scope remains unchanged.

## Date
2026-11-06

## Context
Audit D11 lacked maximum-TTL and denial-path evidence. UA5.1's lifetime 4,096
redemption cutoff stopped useful work permanently. SPIFFE's streaming source can
retain accepted material during reconnects; stream health alone is not freshness.

## Decision
Keep policy uncached. Replace lifetime redemption accounting with a bounded map
of consumed token hash to original grant expiry, protected with the policy read
by one mutex. Never evict a live entry; deny at capacity, prune expired entries,
and fail closed on observed wall-clock rollback. Issuers must never reuse token
values: an operator deliberately reissuing an expired bearer value authorizes that
value again. Restart invalidation continues through the random boot ID.

Acquire a fresh SPIFFE source every five seconds with a three-second budget.
Lease its TLS configuration for 15 monotonic seconds from retrieval start; failed
refresh cannot renew the lease. Check that captured lease again at authorization.
Upstream drop guards cancel superseded source/watch tasks. Require server and
client SVID validity windows no longer than 60 seconds and recheck peer expiry at
request authorization. Actual SPIRE propagation is external to this local bound.
This adapts the [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
and [short-lived SVID pattern](https://spiffe.io/docs/latest/deploying/svids/).

Promote already-locked `x509-parser` 0.18.1 (MIT/Apache-2.0) to an exact direct
dependency for timestamps after SPIFFE TLS verification. No new transitive package,
CA validation implementation, transport, or schema is added. Use fixed typed denial
codes; never log identity, scope, credential, request bytes or library error detail.

## Alternatives and consequences
Unbounded replay tombstones leak memory; live-entry eviction enables replay; a
lifetime counter denies availability permanently. Provider health/last material
change timestamps cannot prove freshness of an unchanged authoritative bundle.
Periodic fresh acquisition costs one local stream establishment per five seconds;
credential rotation continues through the upstream SPIFFE/rustls adapter.

**BEHAVIOR-ADJACENT:** workloads with long-lived SVIDs now fail closed. Provision
SPIRE TTLs whose complete validity including backdating fits 60 seconds before
rollout. Rolling back restores previous unbounded reconnect retention and the
lifetime redemption cutoff; boot-bound policy must be reprovisioned on any restart.

The longer live tests exposed a fixture allocation defect: SeaweedFS's default
seven-volume growth filled the two-slot server before the bucket's collection
could allocate. F-live now primes the default collection and permits fourteen
32-MiB slots (seven each for default and bucket collections). Both allocations
and conditional create/overwrite/read assertions remain mandatory. This corrects
the required local harness, not production storage behavior or the milestone plan.
