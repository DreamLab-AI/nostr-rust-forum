# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in nostr-rust-forum, please report it
responsibly. Do NOT open a public GitHub issue.

- **Preferred:** Open a [GitHub Security Advisory](https://github.com/DreamLab-AI/nostr-rust-forum/security/advisories/new)
- **Alternate:** Email security@dreamlab-ai.com

We will acknowledge receipt within 48 hours and aim to provide a fix or
mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.0.0-rc7 | Yes (current) |
| 3.0.0-rc6 | Security fixes only |
| 2.0 | Security fixes only |
| < 2.0 | No |

## Past Security Fixes

### v3.0.0-rc7 (Security Audit Sprint + Governance)

Twelve security fixes applied across the ecosystem (see CHANGELOG.md
[Security Audit Sprint] entry). Key fixes:

- **P0-01**: PRF salt now server-derived, preventing client-controlled salt injection
- **P0-02**: Admin model checks both members and whitelist in relay auth
- **P0-03**: Replay DB binding corrected to REPLAY_DB in relay wrangler.toml
- **R2-P0-01**: /pay/.cleanup endpoint now requires NIP-98 auth guard
- **P1-18**: Job settle/cancel operations are atomic via UPDATE...WHERE
- **P1-19**: Job IDs generated via CSPRNG (getrandom)
- **P1-20**: Deterministic invite code fallback removed

The Agent Control Surface Protocol (kinds 31400-31405) uses the existing NIP-98
auth stack for all governance endpoints. Agent pubkeys must be admin-registered
in the `agent_registry` D1 table before they can publish governance events.

### v3.0.0-rc4

Two critical vulnerabilities were identified and fixed:

- **C1 -- NIP-44 v2 HKDF conversation-key interop bug.** The previous
  implementation chained HKDF-Extract then HKDF-Expand, producing the wrong
  conversation key and breaking interoperability with all reference NIP-44 v2
  implementations. Fixed by using direct HMAC-SHA256 derivation. Validated
  against paulmillr/nip44 test vectors.

- **C5 -- NIP-42 AUTH challenge CSPRNG.** The relay worker generated AUTH
  challenges using `Math.random()` (a non-cryptographic PRNG). Replaced with
  `getrandom::getrandom`, which delegates to `crypto.getRandomValues` on the
  Cloudflare Workers runtime. Predictable challenges allow an attacker to
  forge AUTH responses.

All cryptographic operations delegate to NCC-audited RustCrypto crates (k256,
chacha20poly1305, hkdf, hmac, sha2). No hand-rolled cryptography.
