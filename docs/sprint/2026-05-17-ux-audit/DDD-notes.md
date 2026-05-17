# DDD notes — bounded contexts touched by 2026-05-17 sprint

## Bounded contexts in `nostr-bbs-forum-client`

| Context | Aggregate roots | Owner module |
|---------|----------------|--------------|
| **Identity** | `AuthState` (privkey, pubkey, mode) | `auth/` |
| **Routing & Shell** | `Router`, header nav, breadcrumbs | `app.rs` |
| **Channel directory** | `ChannelStore` (kind-40 list, kind-42 events, derived counts) | `stores/channels.rs` |
| **Message authoring** | `ChannelPage`, composer, send-event | `pages/channel.rs`, `pages/chat.rs` |
| **Notifications & Bookmarks** | `NotificationStore`, panel registry | `stores/notifications.rs`, `panel_registry.rs` |
| **PWA shell** | service worker, offline cache | `main.rs`, `sw.js` |
| **Admin** | mod actions, audit log | `admin/*`, `pages/admin.rs` |

## Sprint changes by context

### Routing & Shell
- New value object **`AppPath`** — a base-relative path (invariant: never contains `FORUM_BASE`). Functions:
  - `current_app_path(&Location) -> AppPath` (strips base)
  - `login_redirect_target(AppPath) -> AppPath`
- Service worker registration moves from "browser-relative URL" to "absolute URL with explicit scope".
- ADR-090 documents the invariant.

### Channel directory
- Remove `message_counts` field. Add derivations on `ChannelStore`:
  - `count_for(cid) -> usize`
  - `total_messages() -> usize`
- New behaviour `ChannelStore::ensure_subscribed(cid_or_slug)` — idempotent self-bootstrap (ADR-092).
- `channel_info`'s lookup becomes reactive — a `Memo` that re-runs on `store.channels` change.
- Cache schema (`CachedData`) drops `message_counts`. Forward-compat: serde ignores unknown fields.

### Identity
- `AuthState::sign_event` invariant unchanged, but the **AUTH-signer registration** in `app.rs` gains a precondition: only register if `privkey.with_value(|p| p.is_some())`. On `is_authenticated → false`, call `relay.clear_auth_signer()`.
- Local-key bootstrap (session.rs:289-306) surfaces an explicit "Session expired — please re-paste your key" toast instead of half-authed UI.

### Admin
- Non-admin landing on `/admin` triggers `announcer.push(Severity::Warn, "Admin access required")` **before** navigate to `/chat`.

### PWA shell
- SW registers absolutely. Build pipeline cleans `dist/community/snippets/` before each Trunk run to remove stale bundles (Bug #19).

## Ubiquitous language

| Term | Meaning |
|------|---------|
| **AppPath** | A path **inside the forum app**, base-relative, always starts with `/`, never contains `FORUM_BASE`. |
| **BrowserPath** | Full URL pathname as the browser sees it (includes `FORUM_BASE`). Obtained from `Location.pathname`. |
| **cid** | A channel's NIP-28 event id (hex). Source of truth for the channel directory. |
| **slug** | A human-readable channel handle (e.g. `home-lobby`). May appear in URLs. Must resolve to a cid via store lookups before use. |
| **section** | A NIP-29-style grouping tag attached to a channel (e.g. `minimoonoir-events`). Lookup-equivalent to slug for the resolver. |
| **post count** | `channel_messages[cid].len()`. Never a separate counter. |

## Anti-patterns (codified)
- ❌ `nav(&location.pathname.get(), …)` — always strip base first.
- ❌ `format!("./{}.js", x)` for assets that must work at any route — use `base_href`.
- ❌ Independent counters whose value should equal a `Vec::len()` — derive instead.
- ❌ A page that displays data without owning its data subscription.
