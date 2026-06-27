# nostr-bbs-bbs-client

A retro **ASCII/BBS terminal** face for the nostr-rust-forum kit — a Leptos
CSR/WASM app served at `/community/bbs/` and driven entirely by `forum.toml`.

It is a *face* over the kit's real infrastructure, not a separate app:

| BBS screen | Kit capability |
|---|---|
| Message Base | config-driven **zones/boards** (`[[zones]]`), kind-40/42, deny-by-default relay reads |
| File Base | **Solid pod** browser — WebID-owned storage (`solid_pod_rs::webid`) |
| Node List | **relay** + federation **mesh** peers |
| User List | members as **`did:nostr` WebID** profiles (`nostr_bbs_core::did`) |
| Chat | live channel + encrypted **DMs** (NIP-44/59) |
| Door Games | **agent control panels** — the human-in-the-loop governance plane (`nostr_bbs_core::governance::PanelDefinition`) |
| Code Exchange | shared snippets / pod files |
| System Info | node / relay / pod / **identity** status |
| Settings | theme · identity · node |
| Help | about |

## Configuration (`forum.toml` → `window.__ENV__`)

```toml
[branding]
theme      = "amber"        # amber | green | purple | sky  (BBS palette)
node_name  = "DREAMLAB BBS" # masthead + status bar
location   = "Manchester, UK"
banner_url = ""             # optional ASCII-art / image
logo_url   = "…"

[[zones]]
id         = "public"
accent_hex = "#3b82f6"      # per-board accent colour
```

Projected globals: `THEME`, `NODE_NAME`, `LOCATION`, `BANNER_URL`, `LOGO_URL`,
`RELAY_URL`, `POD_API`, `ZONE_CONFIG`, and optionally `VIEWER_PUBKEY` — the same
`__ENV__` channel the main forum client already uses.

## Keyboard model

`1`–`9`,`0` open a board · `/` command line · `ESC` back · `↑↓`/`j`/`k` move ·
`ENTER` select · `T` cycle theme · `?` help.

## Build (host site integration)

```bash
trunk build --release --public-url /community/bbs/
# → dist/community/bbs/ ; copy into the branded site's deploy and inject the
#   branding keys into window.__ENV__ alongside the existing set.
```

Pure logic (`config`, `theme`, `menu`, `agent`, `identity`) is unit-tested on the
native target; `cargo test -p nostr-bbs-bbs-client`.
