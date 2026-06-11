# nostr-bbs-setup-skill

Provider-abstracted operator-onboarding skill for nostr-bbs deployments.
Implements ADR-079.

## What it does

Walks an operator from `git clone` to "running forum" across five custody
tiers / hosting providers. The skill emits a populated `forum.toml`,
provisions the upstream resources (D1, KV, R2, Routes, Domains), and writes
back the per-worker `wrangler.toml` overlay.

## Status

**Scaffold only.** Each `Provider` impl carries a `todo!()` body documenting
the contract; full implementation lands in Sprint v12+ per the PRD-012
Phase X3 plan.

## Provider matrix (per ADR-079 §4)

| Tier   | Provider                  | Custody             |
|--------|---------------------------|---------------------|
| tier-1 | `SelfHostProvider`        | Operator-managed VM |
| tier-2 | `CloudflareWorkersProvider` | CF Workers Secrets |
| tier-3 | `FlyDotIoProvider`        | Fly.io Secrets      |
| tier-4 | `TurnkeyProvider`         | Hosted (this kit)   |
| tier-x | `KubernetesProvider`      | K8s Secret resource |

## License

AGPL-3.0-only.
