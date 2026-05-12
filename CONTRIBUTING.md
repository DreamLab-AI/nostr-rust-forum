# Contributing to nostr-rust-forum

Thank you for your interest in contributing. This document covers the essentials.

## Getting Started

```bash
rustup target add wasm32-unknown-unknown
cargo build --workspace
cargo test --workspace
```

## Branch Conventions

- `main` -- stable, tagged releases only
- `dev` -- integration branch for in-progress work
- `feature/<name>` -- new features (branch from `dev`)
- `fix/<name>` -- bug fixes (branch from `dev`, or `main` for hotfixes)

## Running Tests

```bash
# Full workspace test suite
cargo test --workspace

# Single crate
cargo test -p nostr-bbs-core

# Governance domain model tests (19 tests)
cargo test -p nostr-bbs-core governance

# WASM compilation check (forum client does not run native tests)
cargo check --target wasm32-unknown-unknown -p nostr-bbs-forum-client
```

## Linting and Drift Detection

Before submitting a PR, run both lint scripts:

```bash
# Anti-drift lint (ADR-077 P3): rejects stale verification key suite
# identifiers, unauthorized DID-Document emitters, and leaked operator branding
scripts/anti-drift-lint.sh

# Sync cross-substrate test fixtures from VisionClaw (optional locally,
# required in CI). Use --verify to check without overwriting.
scripts/sync-fixtures.sh --verify
```

## Code Style

- Follow standard `cargo fmt` formatting
- All public items require doc comments
- Crate names use the `nostr-bbs-` prefix
- Operator-specific branding must not appear in kit source; operators inject
  branding via their `forum-config/` overlay package

## Pull Request Process

1. Create a feature or fix branch from `dev`
2. Make your changes with clear, atomic commits
3. Ensure `cargo test --workspace` passes
4. Ensure `scripts/anti-drift-lint.sh` exits cleanly
5. Open a PR against `dev` with a description of what changed and why
6. At least one maintainer review is required before merge

## Normative Specifications

Cross-substrate normative decisions (ADRs, PRDs, DDD bounded-context maps)
live in the [VisionClaw monorepo](https://github.com/DreamLab-AI/VisionClaw)
under `docs/`. If kit code diverges from a VisionClaw normative document,
that is a bug in this repository.

## Security

If you discover a security vulnerability, do NOT open a public issue. See
[SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be dual-licensed under
MIT and Apache 2.0, consistent with the project license.
