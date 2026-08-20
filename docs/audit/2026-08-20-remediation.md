# Full Audit Remediation — nostr-rust-forum

**Date:** 2026-08-20  
**Baseline:** `0d3edb6e74cf8a3c83d160e91d38f0cf365f3886`  
**Status:** All findings from `2026-08-20-full-codebase-audit.md` remediated in the current working tree

## Security and correctness fixes

- Upgraded `nostr` from 0.44.6 to 0.44.7 and `quinn-proto` from 0.11.14 to 0.11.15. The six Nostr advisories and the QUIC advisory no longer apply. The new NIP-44 `MessageTooLong` error is mapped explicitly.
- Preview responses are consumed incrementally through the Workers byte stream. Oversized `Content-Length` values are rejected before reading, and chunked bodies stop as soon as their cap is crossed.
- ACL PUT uses the same 64 KiB capped parser as ACL reads and rejects any document that removes the pod owner's `acl:Control` grant.
- NIP-98 verification now uses the full parsed request URL, including query strings, across auth, relay, pod, and search workers. Auth-worker regression coverage verifies query preservation.
- Inbox objects use a separate, atomic 5 MiB quota account per recipient pod. Inbox traffic can no longer consume the owner's general 50 MiB allocation; update and delete accounting use the same account.
- Anonymous search returns only entries explicitly ingested with `public: true`. Missing visibility—including legacy mapping data—fails closed.

## Completeness and policy fixes

- Full workspace tests, strict Clippy, strict rustdoc, measured coverage, WASM compilation, focused security tests, formatting, and cargo-deny are required CI jobs.
- Added a deploy-time `validate-forum-config` binary and `scripts/validate-forum-config.sh`; CI validates `forum.example.toml` and a deployment `forum.toml` when present.
- Removed the unwired native Git-anchor module and its raw-private-key-in-Git-config behavior. This Worker crate now explicitly delegates native Git service integration to a separately maintained native service and platform secret store.
- Search visibility, config validation, advisory exceptions, and anti-drift behavior now have executable checks.
- Removed hard-coded operator branding from production HTML/UI defaults and the special operator zone theme. The anti-drift lint ignores trailing Rust test modules and comments while continuing to scan production code and assets.
- Cleared all formatting, Clippy, and strict rustdoc failures. Full tests, Clippy, and docs are no longer advisory.
- Documented every unavoidable transitive RustSec warning with owner, rationale, removal target, and 2026-11-20 review date in `docs/security/advisory-exceptions.md`.

## Verification evidence

The following commands completed successfully against the remediated working tree:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings -D rustdoc::broken-intra-doc-links' cargo doc --workspace --no-deps
cargo check --workspace --target wasm32-unknown-unknown
cargo test --workspace --all-targets --all-features
bash scripts/security-audit.sh
cargo deny check
bash scripts/anti-drift-lint.sh
bash scripts/validate-forum-config.sh forum.example.toml
git diff --check
```

`cargo llvm-cov --workspace --all-features --summary-only` also passed and measured the current workspace at **31.58% line coverage**. CI now generates and retains an LCOV artifact as a required job. This establishes a truthful baseline; it does not claim the repository already meets a higher target.

The Rust toolchain emitted a cache-cleanup warning for a read-only registry file and a future-incompatibility notice for the documented transitive `proc-macro-error2` exception. Neither affected command exit status or repository output.

## Remaining external assurance boundary

No deployed Cloudflare target or authenticated browser environment was supplied. Consequently, production DAST and end-to-end WCAG/browser validation remain deployment verification activities rather than source-tree defects. The repository-side build, test, dependency, configuration, policy, and coverage gates are now enforced and green.
