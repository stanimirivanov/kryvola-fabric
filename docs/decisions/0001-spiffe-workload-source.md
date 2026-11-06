# ADR-001: Use a rotating SPIFFE Workload API source

## Status
Proposed with M1-PR5-R1 (#35); restores the agreed M1-PR5 identity boundary.
This records implementation choices, not an amendment to the M1 plan.

## Date
2026-11-06

## Context
The original static CA and leaf-fingerprint mode authenticated generic mTLS,
not SPIFFE/SPIRE workloads (audit D01). Implementing URI extraction alone would
still leave credential provisioning, bundle validation and rotation outside the
planned provider boundary.

## Decision
Adapt the upstream [rust-spiffe](https://github.com/spiffe/rust-spiffe) X.509 source
and rustls server builder through a narrow runtime adapter. Pin `spiffe` 0.19.0
with `x509-source`, `spiffe-rustls` 0.11.0 with `ring`, and
`spiffe-rustls-tokio` 0.7.0 without default features. Select the configured server
SPIFFE ID explicitly, constrain peer trust to its local trust domain, fail closed
on terminal source closure, and pass the verified peer ID to exact Kryvola grants.
Do not accept a static-CA or fingerprint fallback. rustls session resumption is
disabled by the builder. The source owns private material; it never enters control
messages, policy, or application logs.

The exact lock adds 33 packages, all declaring MIT and/or Apache-2.0 licenses,
including the three Apache-2.0 SPIFFE adapters. Incremental weight includes
Tonic/prost Workload API transport, X.509/ASN.1 parsing, PKCS#8, arc-swap and
source-watch utilities; existing Tokio, ring, rustls and prost versions are reused.
JWT and alternate crypto-provider features are disabled. Reproduce the license
inventory with `cargo metadata --locked --format-version 1` against the preceding
Cargo.lock. This is a deliberate dependency cost instead of bespoke authentication.

Use the official [SPIRE 1.16.0 release](https://github.com/spiffe/spire/releases/tag/v1.16.0)
(Apache-2.0), checksum-pinned in the fixture installer, to exercise actual Workload
API delivery and both server/client SVID rotation. Fixtures require Linux x86_64,
local process/socket access and OpenSSL; they are not production SPIRE manifests.

## Alternatives considered
Retaining generic CA/fingerprint policy violates the planned identity boundary.
Hand-parsing URI SANs with static PEM trust would omit provider integration and
rotation. Platform deployment manifests belong to later Platform work.

## Consequences
The runtime CLI, local grant selector and Rust Authorizer peer parameter change
intentionally. Replace old policies atomically when starting the new CLI; revert
code together with provisioning/policy configuration for rollback. Upload storage
keeps its existing internal field name but records the SPIFFE ID. Fixture TTLs
are ten seconds; reconnects can retain accepted provider state until SVID expiry.
The maximum revocation/cache TTL, exhaustive audit and redemption-capacity fixes
remain M1-PR5-R2 and are not claimed complete here.

ADR-002 records the subsequent M1-PR5-R2 bounds and replay-retention decision.
