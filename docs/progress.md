# Foundation progress

Issue: #1. Scope: initial M0 repository scaffold, 25 October 2026.

- Implemented: rust control services and separate python orchestration package, versioned spec consumption, isolated architecture controls and diagnostics.
- Verified locally: frozen setup, full foundation checks, isolated negative controls, package/native builds and diagnostics.
- Configured but unverified remotely: the GitHub Actions workflow; branch protection/required checks remain maintainer configuration.
- Not claimed: complete M0 acceptance, full Engine API interoperability, cryptographic feasibility, latency measurements, independent security review or deployment.
- Deferred: later roadmap runtime/crypto features. A disabled capability is an explicit incomplete milestone, not an alternate implementation.
- Next: KRY-011/012 identity and immutable artifacts, after spec KRY-002/003/004/005 are reviewed.

The authoritative [plan](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md) remains in force. Review and update only the affected roadmap evidence; no later milestone is marked complete by this scaffold.

## Observed acceptance evidence

A new disposable environment passed `uv sync --locked --no-editable`. The installed wheel loaded from that environment rather than the source checkout, and its packaged data/diagnostic worked. Diagnostics: `uv run --locked python -m kryvola_fabric; cargo run --locked -p kryvola-fabric-core --example inspect`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.

## M0-PR14: bounded control descriptor validation

27 October 2026, issue #3: adopted the merged spec snapshot `1a5b57a590487ba116913050af8041f5e5f1fb52` / `0.1.0-preview.10` with unchanged generated/native artifacts, matching provenance and verified private wheel assets. [Rust/Python wrappers](control-validation.md) add strict Protobuf/schema/correlation validation, nested unknown-field rejection and serialized control/Temporal budgets while preserving the old Rust size helper. Fixed safe errors retain no library diagnostic/cause. No workflows, authentication service, registry, key custody, authorization or proof/ciphertext processing is implemented; M0 remains partial.

Local verification covers Python formatting/lint/types, small unit/provenance checks and rustfmt. Rust compilation/Clippy/tests, wheel build/isolation and the full canonical fabric harness are delegated to existing PR CI as requested. Hosted CI results are not claimed.

## M0-PR30 — Temporal-to-Ray fixture

Issue #5 adds an opt-in test-only Temporal worker, fixed reference-only Ray task,
strict pre-dispatch descriptor validation, bounded duplicate/stale observations,
sanitized failures and actual history replay. The full gate owns isolated local
services and cleanup; the wheel gate checks the packaged public wire vector.
See [fixture boundaries and gates](workflow-fixture.md). Registry fences,
authorization, disclosure and durable inference remain M1 work.

Observed locally: formatting/lint, type and architecture checks and 17 Python
tests passed. Native compilation, package isolation and live Temporal/Ray replay
are delegated to pre-PR CI; its result is recorded in the PR. No production
qualification is claimed by this entry.

## Fabric publication prerequisite for M0-PR31

Issue #7 adds a manual main-only experimental Python-wheel publisher. Two staged
builds, packaged-resource checks, a hash-bound licence/lock/SBOM/provenance manifest,
and keyless workflow verification precede a no-replacement draft-to-prerelease
publication. CI tests actual local signature acceptance, wrong keys and tampering;
no private fixture key is uploaded. [Scope and gates](publication.md) distinguish
local qualification from public signer identity and production readiness.

Observed local formatting/lint/type and offline publication tests are recorded
in the PR alongside the full pre-PR CI result. No package has been published by
this implementation; source/generated contracts and runtime dependencies remain
unchanged. M0-PR31 remains dependent on actual reviewed publication and pins.

## M1-PR4 runtime foundation

`cargo run --locked -p kryvola-fabric-core --bin fabric-runtime` prints its
ephemeral IPv4 loopback address. `GET /healthz` accepts an empty body and reports
process health. Other routes deny access. The shell caps request bodies at
64 KiB, including chunked requests, and times out body reads after two seconds.
Its application errors are fixed JSON messages.

Run the live fixture gate on a local Linux x86_64 Docker Engine with Compose:

```sh
uv run --locked --extra conformance python tools/runtime_integration.py ci
```

The gate uses digest-pinned PostgreSQL, SeaweedFS and AWS CLI images in a unique
internal Compose project. It publishes no non-loopback ports and generates private, temporary
credentials for each run. It checks SQL commit and rollback, S3 conditional
create, the rejection of a second write, and preservation of the original bytes.
It tears down its project and volumes on success or failure. Full verification
runs this gate alongside the Rust socket tests. The PostgreSQL and S3 probes
exercise the services directly. Runtime clients and authenticated endpoints
belong to later slices.

## M1-PR5 workload authorization

Run `fabric-runtime --spiffe unix:///path/to/agent.sock spiffe://DOMAIN/runtime POLICY_JSON`
to enable artifact authorization. The SPIFFE Workload API supplies the selected
server X.509-SVID, private key and trust bundles; updates rotate TLS material
without restart. The configured server identity must be available from that
provider. TLS verifies key possession, chain, validity and SPIFFE identity in the
local trust domain. Only the verified SPIFFE ID enters Kryvola policy evaluation;
headers and common names cannot supply identity. Plaintext mode remains a bounded,
health-only shell. No production SPIRE deployment is included.

**Compatibility change (M1-PR5-R1):** `--mtls` and fingerprint grants are removed.
Operators must provision a Workload API socket and replace `certificate_sha256`
with the exact `spiffe_id` string. Legacy fields fail closed. Grants now survive
SVID rotation for the same workload. Internal upload permits retain their existing
`certificate` storage field but bind it to the verified SPIFFE ID; no SQL schema
migration or externally served upload route is introduced.

The process prints its address and public boot ID. An operator with exclusive
write access to the policy directory atomically replaces a JSON object containing
`boot_id` and up to 256 `grants`. Each grant contains `spiffe_id`, `token_sha256`
(SHA-256 of the ASCII bearer token), `scope` (the Spec v1 authorization request),
and integer `expires_unix_ms`. Generate a fresh random 32-byte lowercase-hex token
and send it only in the HTTPS Authorization header. The grant matches one exact
workload, tenant, operation, workflow/attempt epochs, fence, manifest and purpose.
Only expiries within the next 60 seconds are accepted. Redemption consumes the
token through the grant's original expiry; a new boot ID invalidates old grants.
M1-PR5-R2 retains at most 4,096 **unexpired** consumed token hashes. Capacity denies
new redemptions while full, then recovers as entries expire; live replay records
are never evicted. Policy edits cannot shorten that retention. Issuers must use a
fresh random token for every grant, never reissue an expired token value, and keep
policy files bound to the current boot. A wall-clock rollback below the observed
redemption high-water mark fails closed until time catches up.

Policy is reread on every check, so replacement/removal applies on the next read.
M1-PR5-R2 gives each freshly acquired Workload API source a **15-second monotonic
lease**, measured from retrieval start. A fresh source is acquired every five
seconds with a three-second refresh budget. Failed refresh does not extend the
lease. Both TCP admission and authorization after body reading check the captured
lease, so established connections cannot extend stale trust. Upstream source/watch
tasks cancel when their configuration is dropped. TLS resumption stays disabled.

Both server and peer SVIDs must have **at most 60 seconds total validity**, including
issuer backdating. Configure SPIRE registration TTL accordingly (the live fixture
uses 45 seconds plus SPIRE's ten-second backdating). Certificate expiry is checked
again after body reading. Identity revocation therefore relies on issuance stopping
and the last accepted SVID expiring within 60 seconds; local trust-bundle staleness
is bounded by 15 seconds after the last successful provider retrieval. These are
local enforcement bounds, not a claim about when SPIRE server/agent propagation
finishes. Production propagation and attestation remain Platform responsibilities.
Policy removal/replacement still takes effect on the next read, with no policy cache.

Denial records contain only `runtime_auth_denied` and a closed reason code:
`credential`, `policy`, `expiry`, `replay`, `capacity`, `clock`, `invalid_scope`,
`body`, `deadline`, `handshake`, `identity`, or `provider`. Identity, scope, raw
credentials, parser errors and request bytes are excluded. Live tests exercise
HTTP/TLS denial reasons, concurrent single-use redemption, policy revocation and
provider outage; deterministic Rust tests cover TTL boundaries and capacity recovery.
Authenticated HTTP connections last at most eight seconds, disable keep-alive,
and return only grant expiry. No route serves artifact bytes or replaces SQL fencing.
See [the bounded authorization decision](decisions/0002-bounded-authorization.md).

Install the checksum-pinned local fixture with `uv run --locked python tools/install_spire.py`.
F-live (`uv run --locked --extra conformance python tools/runtime_integration.py ci`)
owns the real SPIRE server/agent authentication suite, in addition to runtime
bounds and storage/broker fixtures. Missing SPIRE binaries fail the gate. The
fixture uses local UID selectors and insecure bootstrap inside a private temporary
directory; it proves provider integration, not production workload isolation.
See [the dependency decision](decisions/0001-spiffe-workload-source.md).

## M1-PR6 PostgreSQL operation registry

The internal Rust registry stores validated immutable operation intent and ordered
input manifest digests. Both operation IDs and idempotency keys are unique within
a tenant. Identical retries return the stored intent. Changed intent conflicts.
Apply the embedded additive migration before serving registry traffic. Roll back
the caller code without dropping the tables or their history.

The coordinator locks the operation row before admitting or renewing an attempt.
An explicit workflow decision supplies the next contiguous attempt epoch, starting
at one. Its fence equals that epoch within the immutable operation/workflow.
Leases use PostgreSQL time and expire after at most 30 seconds, capped by the
operation deadline. An observed expired attempt is marked retired before the
registry returns. Retired epochs survive reconnect and PostgreSQL restart. Use a
reliable database clock for lease deadlines.

The live gate checks the Rust registry over a Unix socket in its private fixture
directory. It restarts PostgreSQL and checks persisted state from a new process.
M1-PR6-R1 wires `POST /v1/operations`, `GET /v1/operations/{operation_id}` and
`POST /v1/attempts/ensure` through the SPIFFE runtime. Add
`--registry DATABASE_URL_FILE` after the existing `--spiffe` arguments to opt in.
The private UTF-8 file contains a PostgreSQL URL of at most 4,096 bytes; grant
read access only to the service. Startup connects with at most eight sessions,
sets two-second statement/acquisition and one-second lock budgets, and applies
the existing additive migrations before printing readiness. Startup errors are
fixed strings; URLs, SQL errors and credentials never enter HTTP bodies or logs.
Without the flag, operation/attempt routes remain disabled. Plaintext mode cannot
enable registry access.

The policy may add `registry_grants` alongside `grants` (at most 256 combined).
Each has `spiffe_id`, `token_sha256`, `expires_unix_ms`, `scope` containing exact
`tenant_scope`, `operation_id`, `workflow_epoch` strings, and `actions` selected
from `CREATE_OPERATION`, `GET_OPERATION`, `ENSURE_ATTEMPT`. These coordinator
capabilities are reusable until expiry (maximum 60 seconds) so identical retries
can reach the idempotent registry. Artifact grants remain one-use and cannot
substitute for coordinator authorization. Both kinds require the current boot ID,
verified workload, fresh policy and monotonic observed wall time. No wildcard
scope or tenant header supplies authority. Read derives tenant from the grant;
create/ensure must match the same scope in their validated body.

Requests/responses use the pinned Spec schemas. Ensure returns an existing live
lease unchanged; there is no invented HTTP renewal route or caller-assigned fence.
The public status projects existing selection, cancellation and deadline state;
it confers no disclosure permission. Conflict/expiry/unavailable responses expose
only canonical Spec codes. F-live races identical and fresh conflicting HTTP
creates, verifies expiry, rejects cross-tenant/workflow/action/credential swaps,
stops/restarts PostgreSQL, and restarts the runtime while preserving the current
successor's exact lease. SQL restart tests persist exact expected epoch/fence/expiry
between processes and verify the next successor advances monotonically.

**Compatibility:** old policy files remain valid in the new binary. On code
rollback remove `registry_grants` from the policy (old binaries reject unknown
fields) and drop the new CLI flag, preserving all operation history. Rotate/reissue
boot-bound grants after restart. Selection, cancellation and release handlers remain
separate slices. See [the runtime boundary decision](decisions/0003-registry-http.md).

## M1-PR7 bounded artifact staging

The internal upload store redeems compute-write grants and binds a reservation to
the exact verified workload SPIFFE ID and request scope. PostgreSQL serializes quota
admission per tenant and part writes per upload. M1-PR7-R1 uses the pinned
`object_store::MultipartUpload` lifecycle for each application part. A fixed
4-MiB buffer reads at most 64 KiB at a time and probes one extra byte; allocation
does not depend on the declared total upload size. One application chunk is one
final S3 multipart part, so the sub-5-MiB final-part exception applies. No parallel
part buffers or custom S3 multipart protocol are introduced.

The SDK's multipart completion overwrites its destination, so every write uses a
fresh private `staging/{upload_id}/{part_index}/{nonce}` key. Nullable `object_key`
in migration 0008 publishes the completed key with the part marker/byte accounting
in the existing SQL transaction. Finalization falls back to the original path for
NULL legacy mappings. Public artifact identities and immutable paths are unchanged;
keys contain no endpoint, bucket credentials, bearer tokens or provider upload IDs.

Read, length, write, completion and permit errors attempt multipart abort and
private-key deletion; cancellation schedules cleanup with 15-second budgets per
abort/delete call. Cleanup attempts deletion even if abort fails and emits only
`upload_cleanup_failed` on background failure. Cleanup stays armed through SQL
preparation; immediately before commit it retains completed bytes because a lost
commit acknowledgement must not delete a possibly referenced object. Completed
orphans remain private and can be swept by the existing upload-prefix reclamation.
A caller must abort/restart an upload after an ambiguous write, as before.

A process crash, runtime shutdown or lost multipart-initiation response cannot
reliably run async abort. Configure backend lifecycle rules for incomplete sessions;
ordinary object listing/reclamation alone cannot remove incomplete multipart data.
Unit tests inject read/write/completion/abort failures and cancellation; F-live
verifies new mappings, legacy finalization, quota/overwrite/cleanup invariants and
no unfinished sessions. M1-PR7-R3 adds the real transport/resource campaign below.

**Rollout/rollback:** quiesce writers and apply the additive nullable migration
before updating the service. New code reads both layouts; rollback to old code
requires draining/aborting newly mapped temporary uploads first, then running
SQLx undo to version 7 with the supplied down migration so old migration validation
accepts the database. The guard refuses rollback while mapped temporary parts
remain. It preserves the nullable column, finalized objects and operation history;
reapplying the up migration is safe. Use an operator-controlled migration runner;
no database rollback endpoint or standalone migration CLI is introduced. The caller still supplies a
bounded PostgreSQL pool, a private S3 store and tenant quota.

The live gate now exposes the fixture S3 service on an ephemeral IPv4 loopback
port for the Rust client. PostgreSQL remains on the private Unix socket. No
readable artifact reference is introduced.

M1-PR7-R2 adds opt-in SPIFFE-authenticated `POST /v1/uploads`, binary
`PUT /v1/uploads/{id}/parts/{index}`, canonical manifest
`PUT /v1/uploads/{id}/manifest`, and `POST /v1/uploads/{id}/abort`. Each
request redeems a fresh compute-write token bound to the exact workload, tenant,
attempt and manifest commitment. The registry operation lock protects current-fence
validation through the upload mutation; cancellation/selection and quota admission
serialize with it. PostgreSQL lease and operation deadlines, the live SVID expiry,
and provider freshness bound the permit throughout streaming.

Parts require a positive Content-Length, at most 4 MiB, and stream directly into
the bounded multipart adapter; they bypass the 64-KiB control-body collector.
Control and canonical manifest bodies remain capped at 64 KiB. An abort commits
unreachability before cleanup. Staged manifests remain private and write-once;
no GET, finalization or ArtifactRef endpoint is enabled by this slice.

Start with `--spiffe ENDPOINT ID POLICY --registry DB_URL_FILE --uploads S3_CONFIG_FILE`.
The operator-private regular JSON file is capped at 16 KiB and supplies `endpoint`,
`bucket`, `region`, `access_key_id`, `secret_access_key`, `tenant_quota_bytes`,
and optional `allow_http` (false by default; true only for local fixtures). Keep
it readable only by the service account. Credentials/URLs never enter grants,
SQL control records or diagnostic output. Omit `--uploads` to disable these routes;
there is no additional migration. F-live requires real SPIRE/HTTPS, PostgreSQL and
S3 evidence for quota races, scope denials, streaming, manifest staging and abort.
See [ADR-005](decisions/0005-authorized-streaming-uploads.md).

M1-PR7-R3 makes F-live require a 1-GiB reservation / maximum 4-MiB streaming
campaign with Linux runtime RSS sampling (growth <64 MiB; absolute <192 MiB;
kernel virtual peak growth <128 MiB).
A rejected oversized declaration must stay within the same budget. Real partial
TLS disconnect, transport-deadline stall, and mid-body grant expiry each start
with an observed S3 multipart session and must leave no completed staging object,
unfinished session, SQL part marker or received-byte accounting. A fresh grant
retries the same index, then explicit abort removes staging and releases the
reservation. The completion marker and named non-skipped test are both mandatory;
missing campaign evidence fails the gate. These checks use owned fixture services
and a directly extended fixture lease, rather than qualifying a renewal API.
Process-death session lifecycle remains an operator responsibility; finalization
crash coverage remains M1-PR8 work.

## M1-PR8 immutable artifact finalization

The internal finalizer validates the pinned v2 manifest schema and canonical bytes,
then checks the tenant and manifest commitment against the upload grant. It reads
one bounded part at a time, verifies each part and the ordered blob with BLAKE3,
and conditionally creates private immutable objects. PostgreSQL publishes the
metadata handle only after verification and object creation succeed. A retry
checks any preexisting destination part before reusing it. Finalized uploads
reject part writes and aborts.

The returned handle is metadata for internal callers. It grants no read or
release rights. The deployment must keep both object prefixes private and prevent
out-of-band replacement of immutable objects. A failed finalization can leave
unreachable private copies for the later reclamation slice. The live test uses
the pinned Spec golden vector and checks corruption, incomplete input, retry
after an interrupted copy, and concurrent finalization against PostgreSQL and S3.

## M1-PR9 fenced result selection

The internal coordinator registry registers physical execution IDs under a live
attempt. Selection locks the operation row, checks workflow, fence, plan and
policy, and requires a finalized artifact whose upload scope and manifest key
context match. The authenticated coordinator supplies the execution-to-upload
association. Selection rechecks lease expiry using PostgreSQL time when it
inserts the winner.

The single selection row pins the finalized artifact through a foreign key.
A matching retry and lookup return the winner after lease expiry. Conflicting
candidates and new attempts cannot replace it. The selection remains internal
metadata. Cancellation, release and public transport wiring are later slices.

## M1-PR10 cancellation and recovery barriers

The coordinator locks the operation row shared by lease, execution and selection
writes. Cancellation retires the attempts and commits a tombstone and a higher
fence in the same transaction. A retry with the same tenant, operation and
idempotency key returns the recorded fence. An unconfirmed database outcome
returns pending, so callers can retry without assuming cancellation took effect.

Recovery records the next workflow epoch and retires the old operation behind a
higher fence. This records quarantine only. Successor admission requires later
reconciliation and explicit workflow authorization. Cancellation can supersede
the recovery barrier, while a cancelled operation cannot enter recovery.
Committed selection and its pin remain as history. Future release handlers must
check the barrier under the operation lock. Public authentication and Temporal
cleanup remain separate slices.

## M1-PR11 artifact retention and reclamation

The internal retention API records expiring workflow, key-context and audit
pins. Repeating a pin can extend its expiry. A selected result remains pinned
by its registry foreign key. The dry run reports up to 100 eligible uploads
using PostgreSQL time and the caller's retention window.

Explicit reclamation locks the upload row, rechecks eligibility, and commits
a deletion marker before touching S3. Pinning, selection and staging share
that lock. A retry resumes marked cleanup. Quota returns only after both
private prefixes are cleared and the database rows are deleted. Abort uses
the same deletion path.

Operators can preview eligibility before invoking deletion. Scheduling and
bucket lifecycle handling for objects that arrive after a timed-out remote
write are separate concerns. Keep the staging bucket private.

## M1-PR12 transactional notifications

The operation, selection, cancellation and recovery transactions enqueue
versioned wakeups in PostgreSQL. The migration backfills existing state. The
relay marks a row published only after Redpanda acknowledges the send. The
tenant and operation determine the partition key. Consumers must tolerate
duplicates and reordering, and read current registry state before acting.

The consumer validates bounded, header-free records against the retained outbox
and inserts one durable inbox row per subscriber and event. It acknowledges
the Kafka offset after the database commit. A failed or interrupted receive
requires reopening the consumer from its committed offset. Requeue retained
outbox rows to repair missed notifications. A rejected record goes to the
dead-letter topic with a fixed code and no original payload or key.

Configure broker topics with a 64 KiB record limit. The local Redpanda fixture
uses 24-hour event retention and one-hour dead-letter retention. It exposes a
temporary loopback listener. Production topic provisioning, identities, inbox
draining and Temporal wakeup processing belong to later slices. PostgreSQL
retains the outbox and inbox in this slice. Kafka delivery is at least once.


## M1-PR4-R1 — Adopt M1 contracts and correct runtime errors (issue #31)

Adopt the immutable merged Spec generated/native bundles with all source hashes
verified from the selected archive and offline Git-object manifest membership
checks. Add the bounded compiled runtime JSON adapter and replace private shell
errors with versioned Spec envelopes; preserve default-deny routes and existing
policy behavior. The new source-proof negative test and real HTTP error test failed
before the fixes. Identity-provider and business endpoint work remains in its
planned follow-ups; no publication occurred.

Pre-commit verification: the fast gate, 25 Python tests (including TLS/policy), Rust
workspace tests and the real HTTP error regression passed. Full qualification is
run against the clean committed source because its release harness requires that
state; retained PR verification reports the final live/qualification outcome.

The first full run exposed a missing-certificate TLS-test race: peer rejection
surfaced as BrokenPipeError during the request body write. That specific negative
case now accepts the observed transport failure, while any HTTP response still
fails its assertion and subsequent authenticated requests verify server liveness.
The original traceback is retained in local verification logs.


## M1-PR4-R2 — F-live verifies the bounded runtime (issue #33)

The standalone live gate builds and executes the existing exact Rust runtime
probe inside its owned fixture lifecycle. The probe launches the actual shell and
checks health, deny-by-default routing, bounded error bodies, oversized declared
and chunked bodies, and stalled-request rejection. A successful command with zero
or ignored tests, or a different test name, is rejected. Cold compilation has a separate 600-second budget;
probe execution has 30 seconds. Runtime/cargo children share an owned process group
which is killed and drained on completion, timeout or interruption. The same owned
Compose project is cleaned on failure; existing SQL/S3/broker probes remain required.

Verification: the bypass regression failed before wiring the probe. Focused lifecycle
and failure controls pass; a deliberately unhealthy real shell made standalone
F-live fail and its owned Compose project was removed. The runtime source was
restored, and healthy standalone F-live passed all probes. Full publication qualification
requires a clean committed checkout; its final outcome is retained in the PR.
