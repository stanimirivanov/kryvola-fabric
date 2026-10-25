# kryvola-fabric

Rust control services and separate Python orchestration package. This is an initial M0 foundation, with no production execution or security qualification. Existing Apache-2.0 licensing is preserved.

## Setup and verification

Prerequisites: Python 3.14.7 and uv 0.12.5; Rust 1.98.1 with rustfmt/clippy. Python is pinned in `.python-version`; Rust is pinned in `rust-toolchain.toml` where applicable. Run from this repository root:

```sh
uv sync --locked
uv run --locked python tools/verify.py fast
uv run --locked python tools/verify.py full
uv run --locked python -m kryvola_fabric
```

`fast` runs formatting/lint/type/provenance/dependency checks and Rust fmt/clippy. `full` adds isolated positive/negative controls, Rust tests and a Python wheel build. Missing tools or files fail the command. Apply Python formatting with `uv run --locked ruff format .` and lint fixes with `uv run --locked ruff check --fix .`; use `cargo fmt --all` for Rust; rerun affected checks after changes.

No service credentials or local databases are required for this scope. `spec.lock.json` pins immutable generated spec artifacts; a sibling checkout is unnecessary. Generated structural types are not native decoders or authorization. [Architecture and enforcement](docs/architecture.md), [progress](docs/progress.md), and the source references below describe limits.

## Authoritative context

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

Temporal owns durable logical workflow intent. Ray is disposable compute scheduling; a bridge cannot authorize disclosure. The future SQL registry enforces physical attempt fences. Private decryption keys remain in the owner domain; none of these scaffolds implement custody or a decrypt API.

Next planned work: KRY-011/012 identity and immutable artifacts, after spec KRY-002/003/004/005 are reviewed.
