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

## License

MIT OR Apache-2.0.
