# ADR-003: Expose the existing registry through authenticated runtime routes

## Status
Proposed with M1-PR6-R1 (#39), restoring the agreed runtime wiring and D12 evidence.
No amendment to the authoritative M1 plan is claimed.

## Date
2026-11-06

## Decision
Use the existing SQLx transactional registry behind the pinned Spec create/read/
ensure schemas and OpenAPI paths. Keep a small HTTP projection module, cached
validators, bounded pool and SQL deadlines. Read public status from existing rows;
no selection, cancellation or renewal endpoint is invented. The runtime remains
loopback-bound, with registry opt-in only under SPIFFE authentication.

Add separate exact-scope coordinator grants to the operator's local policy.
A verified SPIFFE ID plus matching bearer hash authorizes only listed registry
actions for one tenant/operation/workflow. Grants are reusable for idempotent
retries, expire within 60 seconds, are reread on every call, and retain boot and
clock-rollback binding. Artifact grants cannot authorize registry actions. This
avoids treating compute-read/write permission as workflow authority, or deriving
tenancy from a header/URL alone. No new package or distributed contract is added.

## Consequences
The private URL file bootstraps PostgreSQL; startup applies the existing additive
migrations and fails with a fixed error rather than echoing connection details.
The service credential must have migration rights. Operators opt in with the new
flag and coordinator grants; old configurations retain the health/artifact mode.
Rollback removes the flag and new policy field, preserving database history.
Schema-valid metadata is still subject to transactional idempotency/epoch/fence
checks. Unavailable/ambiguous transport outcomes require an identical retry;
request admission does not retroactively undo a committed operation.

Live evidence covers real SPIRE identity, PostgreSQL and runtime restarts, fresh
conflicting creation races, expired/stale attempts and policy revocation. Tests
mutate only owned fixture rows to force expiry; this is not a production recovery API.
