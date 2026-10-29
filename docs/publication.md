# Experimental fabric publication

This is the publication prerequisite for M0-PR31, not a production release gate.
Only the Python control/conformance wheel is published. Rust crates, container
images, native engines, cryptographic qualification and profile activation are
outside this change. GitHub Releases is the distribution channel; no PyPI
credentials or repository secrets are required.

## Build and verification

`tools/release.py qualify` requires a clean committed checkout and a fresh ignored
`build/publication` directory. It copies tracked source into two fresh directories,
changes only staged package metadata to `0.1.0.dev0+g<FULL_COMMIT_SHA>`, sets
SOURCE_DATE_EPOCH to the source commit time, and compares the wheel SHA-256s.
The checked-in pyproject and lock remain unchanged. This proves repeatability in
one declared toolchain/environment, not cross-platform reproducibility.

The built wheel is imported in isolation with its generated schema resources and
public conformance vector. A strict manifest binds the wheel, Apache licence,
uv.lock, SPDX JSON from Syft and in-toto/SLSA-format provenance. The SBOM describes
the wheel scan; the lock records dependency resolution. Neither asserts a complete
installed dependency SBOM, vulnerability clearance or legal qualification.
Provenance binds the source, package version, lock and consumed spec manifest.
It is a signed publisher assertion, not a claimed SLSA level.

Full CI installs checksum-pinned Cosign 3.1.3 and Syft 1.55.0 explicitly, then
qualifies the package with actual ephemeral-key signatures, wrong-key rejection
and a valid-but-altered manifest rejection. Temporary private signing keys never
enter publication assets. Fast gates do not install these tools or start services.

```sh
uv sync --locked --extra conformance
uv run --locked --extra conformance python tools/install_temporal.py
uv run --locked --extra conformance python tools/install_release.py
uv run --locked --extra conformance python tools/verify.py full
```

These tool installers target Linux x86_64 CI. Offline tests run through the existing
unittest harness, including `tests/test_release.py`. Qualification refuses existing
output rather than overwriting a prior result; use a fresh checkout for a rerun.

## Manual publication and consumer trust

After merge, manually dispatch `.github/workflows/release.yml` on main. Its
read-only qualification job runs the full existing gate, including live
Temporal/Ray replay and package qualification. Only the dependent main-only
publication job gets contents-write and OIDC permissions. It signs the manifest
keylessly, verifies the exact workflow identity, GitHub issuer, source SHA and
workflow_dispatch trigger, then creates `experimental-<FULL_COMMIT_SHA>`.
Assets upload to a draft first; successful upload exposes it as a prerelease.
Existing tags/releases are refused. Failed drafts require maintainer inspection;
there is no automatic deletion, replacement, clobber or retry publication.
GitHub-side immutable-release protection remains a maintainer setting; the
workflow cannot prevent an authorized maintainer changing remote assets later.

A consumer independently selects the expected source and verifies:

```sh
uv run --locked python tools/release.py verify --folder DOWNLOADED_ASSETS --source FULL_COMMIT_SHA
```

The verifier requires the pinned local Cosign tool, exact publisher identity
`https://github.com/stanimirivanov/kryvola-fabric/.github/workflows/release.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`, with transparency and
certificate checks enabled. It rejects changed assets, unexpected files, invalid
versions and production labels. Consumers must additionally pin the expected wheel
and manifest digests, resolve their locked runtime dependencies, and reverify at
use. Do not trust a tag name, self-declared manifest hash or a local CI signature.
No key-based mode is exposed by the publication CLI.

## Prior art

- Existing Hatchling/uv wheel builds and PEP 440 local versions are adapted through
  a staged build; no new Python dependency or version plugin is added.
- [Syft](https://github.com/anchore/syft) (Apache-2.0) supplies SPDX output instead
  of a custom package inventory. [Cosign](https://docs.sigstore.dev/quickstart/quickstart-cosign/)
  (Apache-2.0) supplies signing/verification instead of custom cryptography.
  Both reuse the engines repository's reviewed tool versions/pins via standalone
  adapters; no sibling code is imported.
- GitHub artifact upload/download actions are commit-pinned. Build artifacts are
  transport between jobs, not public release evidence until keyless verification.

Creating this workflow does not publish a package. Publication is a separate
manual action after review and merge; M0-PR31 still needs published fabric and
fake-engine assets and independent pins.
