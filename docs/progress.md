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

On Windows with Python 3.14.7 / uv 0.12.5, `uv run --locked python tools/verify.py full` passed: Ruff formatting/lint, ty type checks, spec provenance and dependency checks, 4 Python tests and 1 Rust boundary test, and Rust fmt/clippy/tests and Python wheel build. Rust 1.98.1 was used for native verification.

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
