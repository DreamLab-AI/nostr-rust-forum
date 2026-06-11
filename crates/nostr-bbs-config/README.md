# nostr-bbs-config

Operator-supplied TOML configuration kit for nostr-bbs deployments.

Implements PRD-012 §5 X1 and ADR-085: a single `forum.toml` file is the source
of truth for every deployment-specific setting. Worker crates in the
`nostr-bbs-*-worker` set load this at startup; the `forum-client` reads its
shape via `option_env!` slots populated at build time.

## Usage

```rust
use nostr_bbs_config::ForumConfig;

let toml = std::fs::read_to_string("forum.toml")?;
let config: ForumConfig = nostr_bbs_config::load_from_str(&toml)?;
```

## Schema

See [`src/schema.rs`](src/schema.rs) for the canonical schema. Major sections:

| Section        | Purpose                                                        |
|----------------|----------------------------------------------------------------|
| `[deployment]` | name + canonical hostname                                      |
| `[webauthn]`   | RP ID + expected origin                                        |
| `[pod]`        | pod base URL + storage backend                                 |
| `[relay]`      | WebSocket URL + ingress policy                                 |
| `[admin]`      | static or D1-resolved admin pubkeys                            |
| `[branding]`   | theme + logo + copy                                            |
| `[[zones]]`    | named zone access rules                                        |
| `[trust]`      | join + post score thresholds                                   |
| `[invites]`    | invite system + welcome bot pubkey                             |
| `[moderation]` | event-kind range (default 30910..=30916)                       |
| `[mesh]`       | federation mode + peer relays                                  |
| `[ratelimit]`  | per-route limits                                               |
| `[features]`   | optional UI features                                           |
| `[custody]`    | operator tier (tier-1 .. tier-4 per ADR-079)                   |
| `[governance]` | Agent Control Surface settings: agent registry mode, default rate limit, governance API path |
| `[nip05]`      | NIP-05 resolver mode, pod base URL, fallback timeout, CORS (ADR-086) |
| `[native_pod]` | Native solid-pod-rs (agentbox) tier: enabled, base URL, allowlist cohorts, git, admin provisioning URL (ADR-093) |

## Validation

`load_from_str` runs semantic validation beyond serde shape-checks:

- `deployment.hostname` must be `https://...` (or `http://localhost` for dev)
- `webauthn.rp_id` must be a bare domain (not a URL)
- `pod.base_url` must be HTTPS
- `relay.url` must be `wss://...`
- `admin.mode` ∈ `{"static", "d1"}`; `static_pubkeys` must be 64-char hex
- `moderation.kinds_lo <= kinds_hi`
- `mesh.mode` ∈ `{"standalone", "federated"}`
- `custody.operator` ∈ `{"tier-1", ..., "tier-4"}`

## License

AGPL-3.0-only.
