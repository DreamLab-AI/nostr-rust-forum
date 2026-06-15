# Maintainers

nostr-rust-forum is maintained by a small group with commit access, working in the open.
Decisions are recorded in issues, PRs, and ADRs.

## Current maintainers

| Maintainer | GitHub | Focus |
|---|---|---|
| John O'Hare | [@jjohare](https://github.com/jjohare) | Project lead; kit architecture, Nostr NIPs, Cloudflare Workers |
| Melvin Carvalho | [@melvincarvalho](https://github.com/melvincarvalho) | Upstream IP; JSS Solid protocol, DID:Nostr, Web Ledgers, identity standards |

## Upstream

This kit is built on [solid-pod-rs](https://github.com/melvincarvalho/solid-pod-rs), a Rust port of
Melvin Carvalho's [JavaScriptSolidServer (JSS)](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer).
JSS is the AGPL-3.0 reference implementation of the Solid Protocol and the canonical source for
the feature set, protocol extensions, and Web Ledger micropayment system that this forum kit consumes.
Protocol-level decisions and spec alignment defer to the upstream JSS issue tracker.

See [.github/CODEOWNERS](.github/CODEOWNERS) for path-level review routing.

## Process

Maintainers follow the same workflow as other contributors (issue → branch → PR → review → merge).

## Becoming a maintainer

By invitation of an existing maintainer, after demonstrated substantive
contribution. No formal vote; existing maintainers make the call and
update this file.

## Security

Security disclosures: use [GitHub private security advisories](https://github.com/DreamLab-AI/nostr-rust-forum/security/advisories/new).
