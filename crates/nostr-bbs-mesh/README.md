# nostr-bbs-mesh

Federation mesh kit for nostr-bbs deployments. Implements ADR-073: per-peer
connection state, NIP-42 AUTH session management, and kind-30033 federated-
broadcast event emission.

## Status

**Scaffold only** — the mesh feature is gated by `[mesh] mode = "federated"`
in `forum.toml` (default `standalone`), and the relay-worker's runtime
continues to short-circuit when in standalone mode. Full implementation
lands in Sprint v12+ per the PRD-012 Phase X3 plan.

## Architecture

This crate provides the *substrate* — abstract traits + state machines — that
concrete worker implementations plug into. The reference Cloudflare Worker
implementation lives alongside `nostr-bbs-relay-worker`; alternative
deployment targets (libp2p, HTTP/3, Tailscale) implement [`MeshTransport`]
themselves.

```text
    [PeerRelay A]                         [Local Relay]
        │                                       │
        │ wss://A/.well-known/nostr.json#mesh   │
        │◀──────────────────────────────────────│
        │                                       │
        │   ["AUTH", <NIP-42 challenge>]        │
        │──────────────────────────────────────▶│
        │   ["AUTH", <signed challenge>]        │
        │◀──────────────────────────────────────│
        │   ["EVENT", <kind-30033 mesh anchor>] │
        │──────────────────────────────────────▶│
        │                                       │
```

## Tailscale Transport

### Alternative to public relays

The mesh crate's peer relay connections can traverse a
[Tailscale](https://tailscale.com) tailnet instead of the public internet.
This keeps relay traffic private between your own infrastructure nodes —
no NIP-42 challenge is exposed to the open web, and latency drops to
single-digit ms on the same tailnet.

### Configuration

In `forum.toml`, point `peer_relays` at Tailscale
MagicDNS hostnames:

```toml
[mesh]
mode = "federated"
peer_relays = ["ws://node.tailnet-name.ts.net:7777"]
```

Replace `tailnet-name` with your actual tailnet domain (visible in the
Tailscale admin console under **DNS**).

### Discovery

Agentbox exposes its Nostr relay on `:7777` via its tailnet hostname.
The mesh crate connects over a standard WebSocket — no Tailscale SDK or
library dependency is required. Any node on the same tailnet can reach
the relay without port-forwarding or TLS certificate provisioning
(Tailscale's WireGuard tunnel handles encryption).

### Cross-network federation

The forum itself runs on Cloudflare Workers and cannot join a tailnet
directly. The mesh relay bridge handles cross-network federation:

```text
CF Workers relay ↔ public wss:// ↔ agentbox relay
                                        ↑
                                  also reachable over
                                  tailnet by other
                                  agentbox instances
```

Agentbox relays are therefore dual-homed: reachable from CF Workers over
the public internet *and* from sibling agentboxes over the tailnet.

## License

AGPL-3.0-only.
