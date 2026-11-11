# M1 Fabric runtime delivery

M1-PR29 adds a separate `fabric-m1-publication-v1` inventory alongside the
unchanged M0 conformance wheel. M1 uses a separate `m1-FULL_COMMIT_SHA`
prerelease and manifest signature. CI qualification publishes nothing.
Production deployment, credential provisioning and profile activation remain
separate. The supported target is Linux x86_64.

| Artifact | Boundary |
|---|---|
| `runtime-SHA.tar` | Release-mode `fabric-runtime`, all ordered SQL migrations, licence, Cargo lock, Rust toolchain and Spec pin. Includes registry/upload services, messaging, maintenance and release decisions. |
| `owner-SHA.tar` | Release-mode `kryvola-owner-agent` and licence only. Provision Secret Service, coreutils timeout and the separately qualified `kryvola-owner==0.1.0.dev2` interpreter. No owner key or compute Python environment is bundled. |
| `kryvola_fabric_workflow-VERSION-py3-none-any.whl` | Python 3.14.7 Temporal workflows, recovery/release activities and host Ray dispatcher. No Ray job worker, owner binding or conformance implementation. |
| `kryvola_fabric_ray-VERSION-py3-none-any.whl` | Python 3.12.14 fixed Ray job entrypoint and metadata codec. No Temporal workflow or owner binding. |

`packaging/m1.json` declares the role APIs. Install the role wheels in different
environments: they intentionally provide disjoint subsets of the
`kryvola_fabric` namespace and must never be co-installed. Hash-pinned
`workflow.lock` and `ray.lock` include complete dependency resolutions. Use
`uv pip sync --require-hashes --python ENV/bin/python ROLE.lock`, followed by
`uv pip install --no-deps` for the verified matching wheel. Register the existing
dependency-injected Temporal Worker APIs as documented in
[durable compute](durable-compute.md) and [release decisions](exact-release.md).
Operator authority, registry and dispatcher connections remain external.

The delivered Ray Dockerfile uses the digest-pinned Ray 2.59.0 image, with
an isolated environment for the locked bridge dependencies and installed wheel.
Base Ray dependencies remain available from the pinned image; the locked
protobuf/jsonschema/gRPC packages take precedence. Build using the verified
publication folder as context. No source mount is required. Qualification
checks exact Python/Ray/gRPC versions and forbidden APIs inside the image.
Its local image tag is a build result, not a registry pin: PR30 must bind
its image digest when composing services.

## Qualification and consumer verification

From a clean committed checkout and fresh ignored `build/m1-publication`:

```sh
uv run --locked --extra conformance python tools/runtime_release.py qualify
```

This builds real release binaries, builds each role wheel twice and compares
hashes, scans delivery assets with pinned Syft and records in-toto/SLSA-format
provenance. The manifest binds source, exact Spec pin, locks, runtime versions,
image recipe, migrations and native shared-library hashes. Native binaries are
qualified against the builder's actual libraries, not claimed portable to every
Linux machine. Consumers must match those libraries or rebuild and requalify
for their target environment. This is not a claimed SLSA level.

The strict verifier checks archive membership/modes, wheel API/dependency and
schema sets, provenance subjects and missing/unexpected assets. Installed
qualification uses fresh directories without source/sibling imports: binary
startup, a fresh workflow venv running the existing real Temporal retry/replay
trace, and the built Ray image. The standard F/F-live checks remain enabled.
The final signature qualification uses actual ephemeral-key Cosign signatures,
wrong-key rejection and validly rehashed tamper rejection. Local fixture
signatures are removed before artifact upload. Tests use controlled registry
and Engine fixtures; native owner crypto qualification remains upstream.

Only the existing manual main-only workflow receives signing/publication
permissions. It keylessly signs M1 separately and verifies the exact identity,
issuer, trigger and source before creating a fresh draft prerelease. M0 and M1
are separate non-transactional releases. If one succeeds and another fails,
inspect the draft/tag state; nothing is deleted, replaced or republished.

Consumers independently pin the expected source and manifest, then use the
matching verifier checkout, including its approved Spec pin:

```sh
uv run --locked python tools/runtime_release.py verify --folder DOWNLOADED_ASSETS --source FULL_COMMIT_SHA
```

Do not trust a tag or self-declared inventory alone. No public local-key mode
is exposed. Strict comparison to this verifier's approved source assets is
intentional: a different version requires its matching verifier.
