# Architecture and harness

Source: design v2 sections 4.3, 5, 6, 7 and 13; plan v2 M0; [schema amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md).

Temporal owns durable logical workflow intent. Ray is disposable compute scheduling; a bridge cannot authorize disclosure. The future SQL registry enforces physical attempt fences. Private decryption keys remain in the owner domain; none of these scaffolds implement custody or a decrypt API.

| Requirement | Governed code/configuration | Evaluation | Limit / review |
|---|---|---|---|
| Runtime/module ownership | `src/`, `crates/` | Compiler/type checker and `tools/architecture.py` | Semantic responsibility remains code review |
| No sibling implementation source dependency | `pyproject.toml`, Python imports, Cargo manifests | AST/manifest check; isolated forbidden-import and sibling-path fixtures in tests | Dynamic imports/native calls and CMake dependency changes require review |
| Contracts come from spec | `spec.lock.json` and vendored artifacts | Commit/repository identity plus SHA-256 manifest/file integrity checks | Build provenance is not cryptographic authorization; update source and pin in a reviewed change |
| Reference-only bounded control | Rust `wire` and Python `control`; pinned descriptor/schema bundles | Golden/negative Protobuf tests, actual byte limits, Temporal aggregate budgets, packaged-asset integrity | Call-site transport hooks, authorization and native ciphertext decoding remain pending |
| No unqualified production claim | Capability diagnostic | Documented inspect command; code review | No inference, crypto qualification or deployed stack |
| Reproducible setup / required checks | Toolchain pins, `uv.lock`, `Cargo.lock`, `tools/verify.py` | README fast/full commands, same commands in CI | Full cryptographic, hardware and operational gates remain deferred |
| Codex guidance | Root `AGENTS.md` | Git-root discovery applies through child working directories; no overrides | Client trust/activation is user-managed; no config or model override is installed |

The custom architecture tool examines declared dependencies and static Python imports, not arbitrary program behavior. Its isolated fixtures demonstrate both valid acceptance and representative failure, including nonzero CLI exit. Required inputs are never optional and failures propagate through the canonical task runner.

[M0-PR14 control validation](control-validation.md) describes the stricter metadata boundary, immutable dual-bundle pin, adopted libraries and remaining runtime gaps. Full CI also verifies the built wheel's private data assets and imports its validator in isolation.

CI is configured on pull requests/main pushes with commit-pinned actions, `contents: read`, no persistent Git credentials and no production secrets. A hosted CI result is not claimed by configuration. Maintainers must enable required status checks (`verify`), review/branch rules and any desired repository security settings; no remote protections are changed here. Local hooks are not merge enforcement.

No `.codex/config.toml` or repository skill is needed for the current workflow. Root instructions link detailed sources on demand and preserve the configured model/reasoning effort. Scoped instruction files are unnecessary because responsibilities do not yet require different agent rules.
