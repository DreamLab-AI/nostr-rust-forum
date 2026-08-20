# Full Codebase Audit — nostr-rust-forum

> **Remediated:** Every finding in this report was addressed in the follow-up
> working tree on 2026-08-20. See
> [`2026-08-20-remediation.md`](./2026-08-20-remediation.md) for the fixes and
> fresh verification evidence. The results below remain the historical
> baseline for revision `0d3edb6`.

**Date:** 2026-08-20  
**Revision:** `0d3edb6e74cf8a3c83d160e91d38f0cf365f3886` (`main`)  
**Scope:** 14 workspace crates, 277 Rust files, approximately 125,037 lines of Rust  
**Method:** Static trust-boundary review, dependency/advisory analysis, compilation and test gates, WebAssembly compilation, Clippy, rustdoc, formatting, anti-drift policy, and revalidation of the 2026-06-27 Agentic QE fleet audit

## Executive conclusion

The repository is **not release-ready at this revision**. The full test suite and WebAssembly build pass, and the serious authorization/XSS defects identified by the June Agentic QE fleet audit have been repaired. However, the locked `nostr` dependency has six current security advisories (four rated high), and two CI hard gates—formatting and dependency policy—fail locally at the audited commit.

This audit found one High, five Medium, and five Low residual issues. The most important code defects are an ineffective preview response-size cap, an ACL write/read size mismatch that can lock an owner out, NIP-98 canonical URLs that omit query strings, and third-party inbox writes being charged to the recipient's storage quota.

This was a source and local-build audit. It did not exercise a deployed Cloudflare environment, perform browser accessibility testing, or run DAST. No coverage collector, `gitleaks`, or Semgrep installation was available, so this report does not claim measured coverage or comprehensive dynamic/secrets/SAST assurance.

## Gate results

| Gate | Result | Evidence / consequence |
|---|---:|---|
| `cargo test --workspace --all-targets --all-features` | Pass | All executed tests passed; no active ignored Rust tests were found. |
| `cargo check --workspace --target wasm32-unknown-unknown` | Pass | All workspace crates compile for the deployment target. |
| `cargo check --workspace --all-targets --all-features` | Pass | Native all-target/all-feature type checking succeeds. |
| `cargo fmt --all -- --check` | **Fail** | Widespread formatting drift. This is a current CI hard-gate failure. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **Fail** | Approximately 13 errors, including dead code, absurd zero comparisons, `too_many_arguments`, `manual_contains`, and iterator/style findings. |
| Strict rustdoc (`-D warnings -D rustdoc::broken-intra-doc-links`) | **Fail** | A public mesh document links to private `Self::capacity`; the forum client has an unresolved `ProfileCache` link. |
| `cargo audit --deny warnings` | **Fail** | Seven vulnerabilities and seven denied warnings. |
| `cargo deny check` | **Fail** | Security advisories in the locked `nostr` version violate policy. This is a current CI hard-gate failure. |
| `bash scripts/anti-drift-lint.sh` | **Fail** | Product-specific operator branding remains in reusable substrate, including production client files. |

The repository contains 1,873 Rust test annotations, but annotation count is not line, branch, or mutation coverage. No coverage threshold is defined or enforced.

## Findings

### H-01 — Locked `nostr` dependency has six current security advisories

**Evidence:** The workspace requests `nostr = "0.44"`; `Cargo.lock` resolves `nostr 0.44.6`. Both `cargo audit --deny warnings` and `cargo deny check` fail. Advisories RUSTSEC-2026-0225 through RUSTSEC-2026-0230 affect this version; four are rated 7.5/high and two medium. All report `>=0.44.7` as the fixed range.

The audit also reports RUSTSEC-2026-0185 for `quinn-proto 0.11.14`, fixed in `>=0.11.15`. The repository explicitly ignores it as native-only, but the exception should be revalidated and time-bounded. Additional denied warnings cover unmaintained or unsound transitive packages including `bincode`, `instant`, `paste`, `proc-macro-error2`, and `event-listener`.

**Impact:** Known flaws in a foundational Nostr implementation remain in the resolved production graph, while dependency policy prevents a clean release.

**Recommendation:** Upgrade and lock `nostr >=0.44.7`, update `quinn-proto` where compatible, regenerate the lockfile, and rerun the complete build/test/audit matrix. Give every advisory ignore an owner, rationale, target removal version, and expiry date.

### M-01 — Preview response caps are applied after full-body allocation

**Evidence:** `crates/nostr-bbs-preview-worker/src/ssrf.rs` defines 2 MiB text and 10 MiB byte caps, but both capped readers first execute `response.bytes().await?` and only then compare the resulting length.

**Impact:** A hostile but otherwise permitted public origin can make the worker buffer the entire response before it is rejected. The advertised limits therefore do not protect memory or upstream bandwidth and create an availability risk.

**Recommendation:** Consume the response as a stream and stop after `limit + 1` bytes. Reject an oversized `Content-Length` early as an optimization, but do not rely on it because chunked or dishonest responses still require streaming enforcement. Add a test with an unknown-length body that exceeds the limit.

### M-02 — ACL writes can exceed the ACL read cap and bypass the owner-Control invariant

**Evidence:** `crates/nostr-bbs-pod-worker/src/acl.rs` caps ACL parsing at 64 KiB. The ACL PUT path in `lib.rs` accepts the worker's general 50 MiB body limit, validates arbitrary raw JSON-LD with ordinary `serde_json`, and stores it. Subsequent authorization loads use the capped parser and treat an oversized ACL as unusable. The structured delegation shortcut preserves owner Control, but a caller with Control can submit raw JSON-LD that removes the owner's Control grant or delegates Control more broadly.

**Impact:** The server can return success for an ACL document it will not later honor, causing denial-by-default lockout. Raw ACL input also bypasses an explicitly documented ownership invariant.

**Recommendation:** Enforce the same `MAX_ACL_DOC_BYTES` before accepting an ACL write, parse through one shared capped parser, and verify the resulting document grants the owner DID `acl:Control` on the protected resource or applicable default. Prefer a typed ACL mutation API if arbitrary replacement is unnecessary.

### M-03 — NIP-98 verification omits query strings from the signed URL

**Evidence:** Auth admin URL construction, relay whitelist handling, pod authorization, and search ingest form the request URL as `origin + path`. Query parameters are omitted. The official [NIP-98 specification](https://github.com/nostr-protocol/nips/blob/master/98.md) requires the `u` tag to exactly match the absolute request URL, including query parameters.

**Impact:** Query parameters on authenticated requests are not cryptographically bound to the signer. This weakens request integrity for query-driven operations and causes interoperability failures for conforming clients that sign the complete URL. Replay storage limits reuse but does not repair incomplete request binding.

**Recommendation:** Define one shared canonicalization function that includes scheme, authority, path, and the exact query string, and use it in every signer and verifier. Add positive and negative conformance tests proving query mutation invalidates a token.

### M-04 — Authenticated inbox writers can exhaust the recipient owner's quota

**Evidence:** `crates/nostr-bbs-pod-worker/src/provision.rs` grants every `acl:AuthenticatedAgent` Append on `/inbox/`. POST accounting in `lib.rs` reserves storage against the route owner's quota. No per-writer quota, inbox sub-quota, or writer byte budget was found.

**Impact:** Any authenticated user can fill another user's storage allowance through legitimate inbox appends, blocking the owner's own writes until content is removed.

**Recommendation:** Separate inbox capacity from the owner's general quota and apply writer-keyed byte/rate limits. Preserve Solid inbox semantics while bounding the cost any one authenticated principal can impose.

### M-05 — CI's broad regression gates are advisory

**Evidence:** `.github/workflows/ci.yml` makes full tests, Clippy, and documentation advisory via `continue-on-error`. The final aggregator hard-gates formatting, WebAssembly compilation, a narrower security-test subset, and dependency policy. There is no measured coverage threshold, browser accessibility job, or E2E workflow reference.

**Impact:** Regressions outside the selected security packages—including mesh, search, setup, clients, and upstream compatibility—can merge while the overall CI result remains green. Current full tests pass, but the policy does not guarantee that state.

**Recommendation:** Make full workspace tests, Clippy, and strict docs required after clearing current debt. Add explicit coverage expectations for authorization and parser branches, plus browser-level accessibility and critical user-flow tests.

### L-01 — Anonymous semantic search exposes restricted-event metadata

**Evidence:** `crates/nostr-bbs-search-worker/src/lib.rs` exposes unauthenticated POST `/search` and `/embed`. Search results return event IDs, similarity scores, and total vector count. The index and result schema carry no visibility or zone metadata.

**Impact:** If restricted posts are ingested, an anonymous caller can infer that an event exists and is semantically close to chosen text. Content hydration still goes through relay authorization, so this is a metadata/semantic oracle, not a direct content bypass.

**Recommendation:** Do not ingest restricted events, add visibility metadata and filter results for the authenticated viewer, or NIP-98-gate search and authorize each result.

### L-02 — Deployment-time configuration validation is not evidenced in-repository

**Evidence:** `nostr-bbs-config` clearly documents itself as a build/deploy-time validator, and its README states the deploy pipeline invokes it. Repository-wide search found no `.github` or `scripts` caller of `load_from_str`/`load_from_path`; the only consumers are examples, self-tests, and schema types used elsewhere.

**Impact:** The validation contract may be fulfilled by an external deployment system, but this repository cannot prove malformed `forum.toml` is rejected before projection into Worker bindings.

**Recommendation:** Add a checked-in validation/projection command and require it in CI/deploy workflows, or link and version the external pipeline that owns the guarantee.

### L-03 — Native pod Git anchoring is not production-wired

**Evidence:** `crates/nostr-bbs-pod-worker/src/pod_git_anchor.rs` states that the subsystem is not invoked in production. It also writes a raw private key into local Git configuration when used.

**Impact:** The advertised native persistence/audit feature is incomplete, and future activation would introduce a local secret-handling concern.

**Recommendation:** Either complete the integration with secret-store-backed credentials and end-to-end tests, or remove/feature-gate the dead production claim so operators cannot assume it is active.

### L-04 — Reusable-substrate anti-drift policy currently fails

**Evidence:** `scripts/anti-drift-lint.sh` flags branded operator strings in reusable substrate, including production `forum-client/index.html` and `pages/home.rs`, as well as tests/comments.

**Impact:** White-label deployments can leak project-specific branding, and a declared repository policy is not being maintained.

**Recommendation:** Move defaults into validated deployment configuration, update fixtures/comments where required by the policy, and keep the lint as a hard gate.

### L-05 — Clippy, rustdoc, and formatting debt obscures signal

**Evidence:** Strict Clippy reports dead paths and correctness/style lints; strict rustdoc reports broken links; rustfmt reports broad drift. The forum client contains unused access-loading functions/constants, and the native pod Git path is explicitly unwired.

**Impact:** Advisory failures normalize red CI output and make new regressions harder to distinguish from accepted debt.

**Recommendation:** Clear the existing failures in one bounded maintenance change, then remove advisory status and keep the gates warning-free.

## Revalidation of the June Agentic QE audit

The prior fleet report remains useful historical evidence but its headline High findings are stale at this revision. Direct reinspection confirmed these repairs:

- Relay `COUNT` and live broadcast now share authorization/projection controls with protected read paths; filter caps and rate limits are present.
- Web-of-Trust registration enforcement is wired.
- Stored-content type confusion is removed; pod responses include `nosniff` and a sandboxing CSP.
- `remember_me` defaults off and local-key persistence uses session storage unless explicitly selected.
- Preview egress allowlisting is wired, and IPv6/private-address parsing covers the previously reported edge forms.

Controls that remain notably strong include strict Nostr event verification, D1-backed NIP-98 replay protection, WebAuthn ceremony checks, deny-by-default WAC reads, traversal-safe pod routing, client markdown sanitization, recipient/zone gating, and capped relay filter fan-out.

## Assurance gaps

- No deployed target was provided, so Cloudflare binding, Durable Object, D1, R2, cache, header, and egress behavior were not dynamically validated.
- No browser/a11y run was performed; WCAG conformance is unknown.
- No line/branch/mutation coverage report is available.
- `gitleaks` and Semgrep were unavailable. Targeted source inspection found no committed credential, but that is not equivalent to a full secrets/SAST pass.
- Unsafe code was manually sampled (primarily WASM send wrappers, test wakers, and in-place zeroization); no direct defect was confirmed, but this was not a formal soundness proof.

## Remediation order

1. **P0 / release blocker:** Upgrade `nostr`, refresh the lockfile, resolve the `cargo-deny` result, and make the existing formatting hard gate pass.
2. **P1 / security correctness:** Fix streaming preview limits, unify ACL write/read validation and owner Control, and bind NIP-98 tokens to exact query-bearing URLs.
3. **P2 / resilience:** Isolate inbox quota, hard-gate full tests/Clippy/docs, add coverage and browser/a11y evidence, and clear anti-drift failures.
4. **P3 / completeness:** Prove deploy-time config validation, address search metadata policy, and finish or remove the unwired native Git anchor.

After P0 and P1, rerun every command in the gate table and add regression tests for oversized chunked preview responses, oversized/owner-removing ACLs, NIP-98 query mutation, and cross-user inbox quota isolation.
