# Client Onboarding and Messaging — Sequence Diagrams

Cartography audit. All flows are traced from the **actual source code** in
`crates/nostr-bbs-forum-client/`. File:line references are included in prose
and in the findings section. Paths are relative to
`crates/nostr-bbs-forum-client/src/` unless a crate is named; a range may start
at a leading `///` doc comment.

> **Verified against** `origin/main` `3c48e2656d7cabefa894a59b827f5f0d3a8b32b7`
> (v1.0.0-beta.21-rc.2, 2026-11-22). The previous stamp was the 2026-06-11
> sweep. Since then `dm/mod.rs` was rebuilt around the `Signer` trait,
> `stores/channels.rs` and `relay.rs` gained the NIP-42 receipt ledger, deletion
> sync and split filters, and `zone_crypto/` grew key ownership. Sections 1, 2,
> 4, 5 and 7 have their citations re-derived (several flows changed: signup no
> longer checks username availability, claim and provision run in sequence, DMs
> no longer need a raw key); sections 3 and 6 are redrawn; sections 8 to 11 are
> new (deletion sync, page lookup, per-identity zone keys, key minting).

Markers used in place (collected in `00-anomaly-register.md`): `**Open (Oxx):**`
a gap the code leaves, `**Debt:**` something a reader would flag, `**Drift:**`
a comment or doc that disagrees with the code, `**Invariant:**` a property the
design depends on with the line that enforces it, `**Resolved:**` an earlier
finding the code now fixes. Inside a diagram the same words appear as `OPEN:`,
`DEBT:`, `INVARIANT:` in a note.

---

## 1. Signup Wizard

The wizard is a three-phase component in `pages/signup.rs` (`enum Phase`,
`signup.rs:69-75`). Phase transitions are driven by the `phase: RwSignal<Phase>`
signal; no page navigation occurs until `finish_signup` (`signup.rs:309-316`) is
called at the end of Phase 3.

**Changed since June:** there is no username availability check or debounce any
more (the handle is derived by `derive_username`, `signup.rs:86`); claim and
provision run one after the other inside one `spawn_local`, not in parallel
(`signup.rs:264-298`); the identifiers are behind an "Advanced details"
disclosure (`signup.rs:524-621`); `NsecBackup` is not rendered by signup at all
(it is used only by `pages/home.rs:442`); and a device registration now carries a
signed `device_proof`.

```mermaid
sequenceDiagram
    actor User
    participant SignupPage as SignupPage<br/>(pages/signup.rs)
    participant Auth as AuthStore<br/>(auth/mod.rs)
    participant AuthAPI as Auth Worker<br/>(POST /api/username/claim)
    participant PodAPI as Pod Worker<br/>(POST /pods/pubkey/.provision)
    participant RecoverySheet as RecoverySheet<br/>(components/recovery_sheet.rs)
    participant DevicesUtil as devices.rs<br/>(utils/devices.rs)
    participant Browser as Browser<br/>(download / window.print)

    Note over SignupPage: Phase::Identity (signup.rs:69-75, gate at 385)
    User->>SignupPage: Enter display name, optional real name
    SignupPage->>SignupPage: derive_username(display, pubkey) (signup.rs:86)
    User->>SignupPage: Click "Create my account" (signup.rs:439-446, disabled only while busy)

    Note over SignupPage: do_create (signup.rs:238-305)
    SignupPage->>Auth: register_with_generated_key(display) (signup.rs:259, auth/mod.rs:344-414)
    Auth-->>SignupPage: Ok, keypair generated in-WASM, Signer installed

    SignupPage->>AuthAPI: POST /api/username/claim, NIP-98 signed, body username and optional real_name (claim_username signup.rs:118-168, awaited at 274)
    AuthAPI-->>SignupPage: 200 or error
    SignupPage->>SignupPage: zone_access.refresh() after a successful claim (signup.rs:281)
    SignupPage->>PodAPI: POST /pods/{pubkey}/.provision, NIP-98 signed (provision_pod signup.rs:170-204, called at 290)
    PodAPI-->>SignupPage: 201 Created or 409 Exists, an Err is only warned (signup.rs:288-295)

    Note over SignupPage: phase.set(Phase::Profile) (signup.rs:297)
    Note over SignupPage: Phase::Profile (signup.rs:473-622, gate at 478)
    SignupPage-->>User: Identifiers behind "Advanced details": public ID, WebID, git clone URL (signup.rs:524-621)
    User->>SignupPage: Click "Continue → save my access" (signup.rs:513-519)

    Note over SignupPage: Phase::Backup (signup.rs:624-700, gate at 630)
    SignupPage->>RecoverySheet: render with keys, relay URL, display name, on_ready (signup.rs:641-648)

    Note over RecoverySheet: QR codes, all in-WASM (qr_svg recovery_sheet.rs:60-75)
    RecoverySheet->>RecoverySheet: qr_svg of the /connect#k=nsec link (recovery_sheet.rs:293)
    RecoverySheet->>RecoverySheet: qr_svg of the raw nsec for 0xchat or Amber (recovery_sheet.rs:294)
    RecoverySheet->>RecoverySheet: qr_svg of the relay URL (recovery_sheet.rs:295)
    RecoverySheet->>RecoverySheet: qr_svg of the npub (recovery_sheet.rs:296)

    alt DEVICE_KEYS_ENABLED is true (utils/devices.rs:88-114, fn at 93)
        RecoverySheet-->>User: tear-off section with "Generate device key" (recovery_sheet.rs:589-590, button 609-622)
        User->>RecoverySheet: Click Generate (on_generate_device recovery_sheet.rs:371-391)
        RecoverySheet->>DevicesUtil: register_device_with_master(master_hex, label) (utils/devices.rs:161-206)
        DevicesUtil->>DevicesUtil: derive_subkey(master, "device:uuid") (utils/devices.rs:182-184)
        DevicesUtil->>AuthAPI: POST /api/devices/register, NIP-98 by master, body device_pubkey, label, device_proof (utils/devices.rs:190-199, registration_body 272-295)
        AuthAPI-->>DevicesUtil: 200 OK
        DevicesUtil-->>RecoverySheet: RegisteredDevice with device_pubkey, device_nsec, tag
        RecoverySheet->>RecoverySheet: qr_svg of device_connect_url (recovery_sheet.rs:383-384)
    end

    alt sweep toggle checked (recovery_sheet.rs:349-353, UI 692-707)
        RecoverySheet-->>User: "Keep to one community" instructions (recovery_sheet.rs:709-727)
    end

    User->>RecoverySheet: Click "Download recovery file" or "Print a paper copy instead" (recovery_sheet.rs:731-747)
    RecoverySheet->>Browser: on_download (321-336) or window.print via on_print (338-343), printed.set
    User->>RecoverySheet: Tick the saved-it checkbox (on_toggle_confirm recovery_sheet.rs:345-347)
    Note over RecoverySheet: gate Effect runs on_ready (recovery_sheet.rs:302-307)
    Note over SignupPage: sheet_ready.set(true) (signup.rs:647)

    User->>SignupPage: Click "Done — take me to the forum" (signup.rs:672-683, enabled when sheet_ready or advanced override 674-676, 684-697)
    SignupPage->>Auth: confirm_nsec_backup() (signup.rs:313, auth/mod.rs:282-288)
    SignupPage->>SignupPage: navigate to return_to, default /forums (signup.rs:314-315)
```

**Key invariants:**
- Private key is generated entirely in-WASM; never leaves the browser
  (`auth/mod.rs:344-414`).
- `provision_pod` is non-fatal: a failure is warned and the flow continues
  (`signup.rs:288-295`), because the lazy paths provision again on the first
  avatar upload that gets a 403 or 404 (`pages/settings.rs:654-665`, and
  `utils/pod_client.rs:21-44`, which self-heals through
  `provision_pod_signer`, `utils/pod_client.rs:46-78`).
- The "Done" button is disabled until `sheet_ready || advanced_override`
  (`signup.rs:674-676`). The gate propagates from `RecoverySheet::on_ready` →
  `sheet_ready.set(true)` (`signup.rs:647`).
- `real_name` is admin-only; it goes to the auth-worker with the claim and is
  never published to the relay or written to kind-0 (`signup.rs:118-122`,
  `130-135`, `253-256`).

**Drift:** the module comment at `signup.rs:4-5` still says the real name is
posted to `/api/profile/real-name`; the code posts it with the claim to
`/api/username/claim` (`signup.rs:118-168`).

---

## 2. `/connect` Magic-Link Login

Route `/connect` is intentionally NOT auth-gated — it is the route that
authenticates the device (`app.rs:950-953`).

```mermaid
sequenceDiagram
    actor User as User (phone camera)
    participant QR as Recovery Sheet QR<br/>(printed, browser origin)
    participant Browser as Browser / PWA
    participant ConnectPage as ConnectPage<br/>(pages/connect.rs)
    participant Auth as AuthStore<br/>(auth/mod.rs)
    participant History as window.history

    User->>QR: Scan QR with phone camera
    Note over QR: URL = {origin}/connect#k=<nsec1…><br/>(recovery_sheet.rs:288-290)
    Browser->>ConnectPage: Navigate to /connect<br/>Fragment #k=<nsec1…> is in window.location.hash

    Note over ConnectPage: On-mount Effect (connect.rs:100-134)
    ConnectPage->>ConnectPage: (1) read_key_from_hash()<br/>strips # prefix, strips "k=" prefix<br/>(connect.rs:52-67)
    ConnectPage->>History: (2) history.replaceState(null, "", "/connect")<br/>strip_fragment_from_history() — BEFORE any import<br/>(connect.rs:75-84)
    Note over History: nsec no longer in address bar,<br/>browser history, or back button

    alt key present
        ConnectPage->>Auth: (3) login_with_local_key(key)<br/>(auth/mod.rs:435-513)
        Note over Auth: Accepts nsec1… (bech32 decoded via NIP-19)<br/>or 64-hex, sets privkey + Signer
        Auth-->>ConnectPage: Ok(())
        ConnectPage->>ConnectPage: state.set(ConnectState::Success)
        ConnectPage-->>User: Show success panel + red bearer warning<br/>(connect.rs:153-175)
        Note over ConnectPage: set_timeout_once(1500ms) (connect.rs:117-123)
        ConnectPage->>Browser: navigate to /forums (current_app_path)
    else no key in fragment
        ConnectPage->>ConnectPage: state.set(ConnectState::Error("No sign-in key…"))
        ConnectPage-->>User: Show error + "Go to sign-in" link (connect.rs:177-190)
    else key present but invalid
        ConnectPage->>ConnectPage: state.set(ConnectState::Error(e))
        ConnectPage-->>User: Show error message
    end
```

**Key invariants:**
- Fragment is read synchronously, then stripped, then imported — all three steps
  in one `Effect::new` closure with no `.await` between read and strip
  (`connect.rs:100-134`). The key cannot persist in history.
- The key never reaches the server: URL fragments are not sent in HTTP requests.
- Bearer credential warning is shown in red immediately on success
  (`connect.rs:158-166`).

---

## 3. BBS Navigation: Category → Section → Topic → Reply Threading

Three subscriptions feed the forum views, all opened with a receipt callback so a
page can tell "empty" from "not answered yet" (section 9):

- the **channel list** (`ChannelStore::start_sync`, `stores/channels.rs:356`):
  one REQ with two filters, kinds 40 and 41 with limit 1000 and, separately, kind
  5 with the device's `since` marker (`channel_sync_filters`,
  `channels.rs:1006-1016`; the kind-5 filter `deletion_filter`,
  `channels.rs:974-981`). Since PR #81 they are separate filters so a pile of
  deletions can never crowd the channel definitions out of the row budget
  (`channels.rs:993-1000`);
- the **broad message sync** (`start_msg_sync`, `channels.rs:560`): per-zone `#e`
  filters over the known channel ids plus one broad kind-42 catch-all
  (`message_sync_filters`, `channels.rs:1042`), so a busy zone cannot push a quiet
  zone's history out of its row budget (#81);
- the **per-channel history** (`ensure_subscribed`, `channels.rs:693`): kind 42
  with `#e` of the channel, called by the section page (`pages/section.rs:231`)
  and the thread page (`pages/thread.rs:431`), idempotent per channel.

The message sync no longer starts on the first EOSE. `App` starts it only once
the channel list has *settled*: an authenticated answer, or the deadline
(`channel_list_settled`, `utils/lookup.rs:140`; effect at `app.rs:889-913`),
because its per-zone filters are built from the channels known at that instant
and the pre-AUTH answer omits Hidden-zone channels.

```mermaid
sequenceDiagram
    participant App as App root<br/>(app.rs)
    participant ChannelStore as ChannelStore<br/>(stores/channels.rs)
    participant Relay as Nostr Relay<br/>(WebSocket NIP-01)
    participant CategoryPage as CategoryPage<br/>(pages/category.rs)
    participant SectionPage as SectionPage<br/>(pages/section.rs)
    participant ThreadPage as ThreadPage<br/>(pages/thread.rs)
    actor User

    Note over App: on relay Connected (app.rs:874-884)
    App->>ChannelStore: start_sync(relay), one-time, guarded by sub_id (app.rs:882, channels.rs:356-359)
    ChannelStore->>Relay: REQ [kinds 40,41 limit 1000] and [kind 5 since marker limit 1000] (channels.rs:526, 1006-1016)
    Relay-->>ChannelStore: EVENT kind 40 per channel, kind 41 metadata, kind 5 deletions (channels.rs:398-455)
    Note over ChannelStore: kind 5 goes to on_kind5, which records the observation and folds the deletion (channels.rs:377-390, diagram 8)
    Relay-->>ChannelStore: EOSE with authed flag (channels.rs:462)
    Note over ChannelStore: prune channels the relay did not return, loading false, record channel receipt, save cache (channels.rs:489-505)
    ChannelStore->>ChannelStore: deletion_sync::drive for paging (channels.rs:509-519)

    Note over App: start_msg_sync only once the channel list settled and is non-empty (app.rs:889-913, utils/lookup.rs:140)
    App->>ChannelStore: start_msg_sync(relay) (app.rs:912, channels.rs:560)
    ChannelStore->>Relay: REQ per-zone kind 42 #e filters plus a broad kind 42 catch-all (channels.rs:656-660, 1042)
    Relay-->>ChannelStore: EVENT kind 42 (channels.rs:576-640)
    Note over ChannelStore: admits_message, resolve root e-tag to channel, prepare_incoming decrypts, admits again, insert_message dedups (channels.rs:580-629, 807)

    User->>CategoryPage: open /forums/:category
    CategoryPage->>ChannelStore: sections_for_zone(channels, slug, zones) (pages/category.rs:51, 133-138)
    Note over CategoryPage: Lookup::decide over sections found, channel receipt and deadline (pages/category.rs:140-158)
    CategoryPage-->>User: section cards with per-section count store.count_for (pages/category.rs:597, channels.rs:305)
    opt authenticated and zone access granted (pages/category.rs:228-233)
        User->>CategoryPage: New Topic with title and section
        CategoryPage->>Relay: publish_with_ack kind 42 root, tags e section_cid root (publish_topic_root pages/category.rs:669, publish 735-737)
        Relay-->>CategoryPage: OK, toast with the relay reason on refusal (pages/category.rs:722-733)
    end

    User->>SectionPage: open /forums/:category/:section
    SectionPage->>ChannelStore: ensure_subscribed(relay, channel_id) (pages/section.rs:231, channels.rs:693)
    ChannelStore->>Relay: REQ kind 42 #e channel_id limit 1000 (channels.rs:764-773)
    Relay-->>ChannelStore: EVENT kind 42 roots and replies, then EOSE records the history receipt (channels.rs:759-762)
    Note over SectionPage: Lookup of section then history decides loading, not found, timed out (pages/section.rs:302-322)

    User->>ThreadPage: open a topic
    ThreadPage->>ChannelStore: ensure_subscribed (pages/thread.rs:431)
    Note over ThreadPage: topic_root is the kind 42 in channel_events whose id matches the slug (pages/thread.rs:485-506), Lookup decides found or not (pages/thread.rs:637-655)
    User->>ThreadPage: write a reply
    ThreadPage->>Relay: publish_with_ack kind 42, tags e channel root, e root_id reply, p root author (pages/thread.rs:826-840, 914)
```

**Key design points:**
- `ChannelStore` subscribes globally once at app root; the pages do not open
  their own kind-40 or broad kind-42 subscriptions (the comment at
  `pages/category.rs:22-25` records the earlier duplicate).
- Message counts are derived exclusively from `channel_messages.len()` at
  runtime and never persisted as an independent field (ADR-091,
  `channels.rs:301-308`).
- The kind-42 subscription still resolves a root `e` tag against the channel id,
  name or section, because legacy relay data tags messages with slugs rather
  than kind-40 ids (`channels.rs:585-610`).
- Every insertion path asks one predicate, `admits_message`
  (`channels.rs:267-299`), so a deletion folded before its target arrives is
  still honoured (diagram 8).

---

## 4. Device Management

```mermaid
sequenceDiagram
    actor User
    participant SettingsPage as SettingsPage<br/>(pages/settings.rs)
    participant DevicesUtil as devices.rs<br/>(utils/devices.rs)
    participant AuthAPI as Auth Worker<br/>(GET|POST /api/devices/*)
    participant ConnectPage as ConnectPage<br/>(pages/connect.rs)
    participant Browser as Phone Browser

    Note over SettingsPage: Gated on window.__ENV__.DEVICE_KEYS_ENABLED (pages/settings.rs:146-148)
    alt DEVICE_KEYS_ENABLED == false
        Note over SettingsPage: Entire Devices section hidden,<br/>no API calls made (pages/settings.rs:1387-1390)
    end

    Note over SettingsPage: On mount, if authed (pages/settings.rs:157-175)
    SettingsPage->>DevicesUtil: list_devices(auth) (utils/devices.rs:208-217)
    DevicesUtil->>AuthAPI: GET /api/devices<br/>NIP-98 signed by master (utils/devices.rs:211-216)
    AuthAPI-->>DevicesUtil: [{device_pubkey, label, created_at, revoked}, ...]
    Note over DevicesUtil: Accepts bare JSON array OR {devices:[...]} envelope<br/>(utils/devices.rs:297-311)
    DevicesUtil-->>SettingsPage: Vec<DeviceKey>
    SettingsPage-->>User: Render device list with Revoke buttons<br/>(active devices only, pages/settings.rs:1424-1468)

    User->>SettingsPage: Click "Add a device"
    Note over SettingsPage: on_add_device (pages/settings.rs:177-202)
    SettingsPage->>DevicesUtil: register_device(auth, label) (utils/devices.rs:116-159)
    Note over DevicesUtil: Via AuthStore.get_privkey_bytes() path
    DevicesUtil->>DevicesUtil: derive_subkey(master, "device:<uuid>")<br/>(utils/devices.rs:132-135 — nostr_bbs_core::derive_subkey)
    DevicesUtil->>DevicesUtil: encode_nsec(device_hex) — in-WASM (utils/devices.rs:138-139)
    DevicesUtil->>AuthAPI: POST /api/devices/register<br/>NIP-98 signed by master<br/>body: {device_pubkey, label, device_proof} (utils/devices.rs:143-152)
    AuthAPI-->>DevicesUtil: 200 OK
    DevicesUtil-->>SettingsPage: RegisteredDevice { device_pubkey, device_nsec, tag }
    SettingsPage->>DevicesUtil: device_connect_url(device_nsec)<br/>= {origin}/connect#k=<device_nsec> (utils/devices.rs:261-270)
    SettingsPage->>DevicesUtil: qr_svg(url) — in-WASM (utils/devices.rs:241-259)
    SettingsPage-->>User: Show /connect QR + URL (scan with phone)
    SettingsPage->>DevicesUtil: list_devices(auth) — refresh list (pages/settings.rs:192-196)

    User->>Browser: Scan QR with phone → /connect#k=<device_nsec>
    Browser->>ConnectPage: login_with_local_key(device_nsec)
    Note over ConnectPage: Device nsec imports identically to master nsec,<br/>relay grants access because device pubkey is registered

    User->>SettingsPage: Click "Revoke" on a device
    Note over SettingsPage: on_revoke_device(pubkey) (pages/settings.rs:204-222)
    SettingsPage->>DevicesUtil: revoke_device(auth, device_pubkey) (utils/devices.rs:219-229)
    DevicesUtil->>AuthAPI: POST /api/devices/revoke<br/>NIP-98 signed by master<br/>body: {device_pubkey} (utils/devices.rs:223-227)
    AuthAPI-->>DevicesUtil: 200 OK (idempotent)
    Note over SettingsPage: Optimistic update: revoked=1 in devices_list<br/>(pages/settings.rs:211-217)
    SettingsPage-->>User: Device shows "(revoked)", Revoke button hidden
```

---

## 5. DM / Gift-Wrap Client Path

The whole path is `Signer`-based now: nothing needs a raw key, so NIP-07
extension users send and receive too. Pages call `auth.get_signer()` and pass an
`Rc<dyn Signer>` (`pages/dm_list.rs:98-116`, `pages/dm_chat.rs:70-95`), after
relay AUTH. Kind 4 uses `nip04_decrypt` (it is NIP-04, not NIP-44). A send
produces **two** wraps, one to the recipient and a self-copy, and the optimistic
local message is re-keyed to the self-copy id. The extended NIP-17 path
(`dm/routing.rs`, `rumors.rs`, `delivery.rs`, `requests.rs`, `consent.rs`, under
`RECIPIENT_KEYS_ENABLED`) is outside this diagram.

```mermaid
sequenceDiagram
    actor Sender
    actor Recipient
    participant DmChatPage as DmChatPage<br/>(pages/dm_chat.rs)
    participant DMStore as DMStore<br/>(dm/mod.rs)
    participant Relay as Nostr Relay
    participant NIP59 as nostr_bbs_core<br/>(gift_wrap.rs)

    Note over DmChatPage: on mount, after AUTH, with auth.get_signer() (pages/dm_chat.rs:70-95)
    DmChatPage->>DMStore: load_conversation_messages (dm/mod.rs:411-464)
    DMStore->>DMStore: fetch_conversations(relay, signer, my_pubkey) (dm/mod.rs:266-318)
    DMStore->>Relay: REQ gift wraps kind 1059 with #p me, and legacy kind 4 authors me and #p me (dm/mod.rs:903-915, 917-954, inbox_filters 956-961)
    Note over DMStore: subscribe_dm_with_auth_retry re-issues the REQ up to 4 times if no EOSE within 3 s (dm/mod.rs:988-991, 1008-1097)
    Relay-->>DMStore: EVENT kind 1059
    DMStore->>NIP59: unwrap_gift_with_signer(event, signer) (dm/mod.rs:1229, in process_gift_wrap_event 1218-1362, core gift_wrap.rs:865)
    Note over NIP59: peels Wrap 1059, Seal 13, Rumor 14 and returns sender pubkey and plaintext
    NIP59-->>DMStore: unwrapped rumor
    DMStore->>DMStore: insert_dm_message, dedup by event id (dm/mod.rs:1428-1454, apply_message 1500-1520)

    Relay-->>DMStore: EVENT kind 4 (legacy)
    DMStore->>DMStore: signer.nip04_decrypt(counterparty, content) (dm/mod.rs:1400, process_kind4_event 1364-1426)

    Sender->>DmChatPage: type and send
    DmChatPage->>DMStore: send_message (dm/mod.rs:466-494) then send_message_to (503-715)
    Note over DMStore: recipient accepted as hex of any case or npub, else "Invalid recipient pubkey" (dm/mod.rs:520-521, canonical_pubkey 1615-1624)
    DMStore->>DMStore: ensure_dm_relay_published, kind 10050 once per pubkey (dm/mod.rs:2007-2065, called at 611)
    DMStore->>NIP59: gift_wrap_pair_with_signer(signer, recipient, content) (dm/mod.rs:655, core gift_wrap.rs:769)
    Note over NIP59: Rumor 14 then Seal 13 then Wrap 1059 with a throwaway key, returned as to_recipient and to_self
    NIP59-->>DMStore: two kind 1059 events
    DMStore->>DMStore: optimistic local insert, re-keyed to the self-copy id (dm/mod.rs:545-553, 573-600, 659-676)
    DMStore->>Relay: publish own copy first, then the recipient's (dm/mod.rs:690-699, delivery::plain_order)
    DMStore-->>Sender: message appears immediately

    Relay-->>Recipient: EVENT kind 1059 addressed to the recipient
    Note over Recipient: the recipient's DMStore unwraps with its own signer
```

**Resolved (June findings F-06 / register O6):** a NIP-07 extension user is no
longer silently skipped. `subscribe_incoming` (`dm/mod.rs:320-368`) and
`fetch_conversations` take `Rc<dyn Signer>` with no early return on a missing
raw key. An extension without NIP-44 gets a state error (`dm/mod.rs:1253-1264`)
and a persistent banner (`pages/dm_list.rs:295-296`, `334-345`).

---

## 6. App-Root Relay Connection, NIP-42 AUTH and the REQ Ledger (PR #91)

`RelayConnection` (`relay.rs:262`) is one socket for the whole app, provided as
context. `App` creates it (`app.rs:448`), then an effect on `is_authenticated`
installs the AUTH signer (async for NIP-07, sync otherwise, `app.rs:461-476`) and
calls `connect()` (`app.rs:478`); signing out disconnects. Sends are paced to at
most 8 frames per second (`MAX_SENDS_PER_SECOND`, `relay.rs:46`, `queue_paced`
`relay.rs:286`) because the relay drops frames beyond its per-IP cap with only a
NOTICE.

What PR #91 added to the handshake:

- **`authenticated` flips only on the relay's `OK true` for the AUTH event.**
  The public `authenticated` signal used to mean "AUTH frame sent". Now the
  frame is recorded as `pending_auth` (`relay.rs:1459-1464`), the relay's `OK`
  with that event id is routed to `on_auth_ok` (`relay.rs:1389-1397`, `960`), and
  only `Accepted` runs `replay_after_auth` (`relay.rs:967-977`), which sets
  `auth_accepted` (`relay.rs:1161`), re-sends the REQs and COUNTs, flushes the
  held writes and finally sets the signal (`relay.rs:1209-1211`).
- **Writes are held until then.** `send_or_defer_write` (`relay.rs:769`) pushes an
  EVENT into `deferred_writes` while the socket is open but AUTH has not been
  accepted, refused or declared unnecessary (`relay.rs:772-781`). Public reads
  are never deferred.
- **Rate-limited AUTH is retried, a refusal is explained.** `classify_auth_ok`
  (`relay/receipt.rs:272-280`): a `rate-limited:` refusal is re-sent up to
  `AUTH_RETRY_LIMIT = 3` (`receipt.rs:42`, `relay.rs:978-1005`); any other
  refusal calls `refuse_auth` (`relay.rs:1006-1008`, `1018`), which records an
  `auth_note`, marks `auth_refused` and releases the held writes so the relay's
  own refusal reaches each publish callback, with `explain_write_refusal`
  (`receipt.rs:227`) turning a bare `auth-required:` into an explanation
  (`relay.rs:1414-1420`).
- **AUTH cannot stall for ever.** `arm_auth_stall_check` (`relay.rs:1046`) asks
  `release_held_writes` (`receipt.rs:214`) whether the handshake on this socket is
  unresolved and `auth_stalled` (`receipt.rs:250`): 60 s without a signature
  (`AUTH_SIGN_TIMEOUT_MS`, `receipt.rs:60`) or 10 s without an answer
  (`AUTH_ANSWER_TIMEOUT_MS`, `receipt.rs:67`). A stall releases the writes through
  `refuse_auth` (`relay.rs:1069-1070`). Timers carry `conn_gen`, bumped per socket
  (`relay.rs:497`, `582`), so a stale timer does nothing.

```mermaid
sequenceDiagram
    participant App as App<br/>(app.rs)
    participant RelayConn as RelayConnection<br/>(relay.rs)
    participant Relay as Relay
    participant Signer as Auth signer<br/>(auth/mod.rs)

    App->>RelayConn: RelayConnection::new (app.rs:448, relay.rs:346)
    Note over App: effect on is_authenticated (app.rs:457-478)
    App->>RelayConn: set_auth_signer or set_auth_signer_async (app.rs:471, 476, relay.rs:422, 429)
    App->>RelayConn: connect (app.rs:478, relay.rs:444, 450)
    RelayConn->>Relay: open WebSocket
    Note over RelayConn: onopen resets auth flags, stamps auth_challenge_at, bumps conn_gen (relay.rs:491-506)
    RelayConn->>Relay: flush queued non-REQ frames, then every subscription REQ with ledger.sent(false) (relay.rs:511-540)
    Note over RelayConn: OPEN (O22): a post made while the socket was closed sits in pending_messages and is flushed here, before AUTH (relay.rs:815-826, 511-517)
    RelayConn->>RelayConn: arm_auth_stall_check(60 s) and authenticated false (relay.rs:541-549)
    RelayConn-->>App: state Connected (relay.rs:553)

    Relay-->>RelayConn: ["AUTH", challenge] (relay.rs:1424)
    RelayConn->>Signer: sign kind 22242 with relay and challenge tags (relay.rs:1435-1444, 1489-1519)
    alt signed
        RelayConn->>Relay: ["AUTH", event], pending_auth recorded, answer timer 10 s (relay.rs:1451-1474)
    else no key, signing failed or denied
        RelayConn->>RelayConn: refuse_auth releases held writes (relay.rs:1494, 1516, 1521, 1018)
    end

    Relay-->>RelayConn: ["OK", auth_event_id, true or false, message] (relay.rs:1384-1397)
    RelayConn->>RelayConn: on_auth_ok, classify_auth_ok (relay.rs:960, receipt.rs:272)
    alt Accepted
        RelayConn->>RelayConn: replay_after_auth (relay.rs:976, 1153)
        RelayConn->>Relay: re-send every REQ with ledger.sent(true) and every COUNT (relay.rs:1165-1176, 1189-1194)
        RelayConn->>Relay: flush deferred writes (relay.rs:1180-1182, 1198-1201)
        RelayConn-->>App: authenticated true (relay.rs:1209-1211)
    else rate-limited and attempts below 3
        RelayConn->>Relay: re-send the AUTH frame after 1 s times attempts (relay.rs:978-1005)
    else refused
        RelayConn->>RelayConn: refuse_auth, auth_refused, writes released with the relay's refusal (relay.rs:1006-1008, 1018-1040)
    end
```

### The per-subscription REQ ledger

A NIP-42 relay evaluates each REQ against the session's authentication *at the
moment it starts it*, so a REQ sent before `OK true` is answered with the
anonymous view, which omits members-only events. The client then replays every
subscription under the same id. The two REQs can be in flight at once and the
relay does not promise to answer them in order (its REQ handler awaits D1,
`relay/receipt.rs:9-10`). `ReqLedger` (`receipt.rs:71`) therefore never guesses
which REQ an EOSE belongs to: `sent(authed)` counts a REQ out (`receipt.rs:97`),
`answered()` counts an EOSE in and reports "authenticated" only when every REQ
sent for the subscription has been answered and the latest went out after AUTH
was accepted (`receipt.rs:109-116`). The result reaches the page as the `authed`
flag of the EOSE callback (`relay.rs:1305-1316`) and is recorded as a
`SyncReceipt` (section 9).

The relay can also drop a REQ with nothing but a NOTICE (its per-IP cap, its
subscription cap), which names no subscription. `arm_req_watch` (`relay.rs:1101`)
is the per-REQ timeout (`REQ_ANSWER_TIMEOUT_MS = 8000`, `receipt.rs:50`, backed
off by `req_watch_delay`, `receipt.rs:238`): `on_watch` (`receipt.rs:131`) says
`Settled`, `Resend` or `GiveUp` after `REQ_RESEND_LIMIT = 2` (`receipt.rs:55`). A
re-send retires the wire id and goes out under a fresh one (`wire_id`,
`receipt.rs:158`, `relay.rs:1131-1136`) after a CLOSE of the old one
(`relay.rs:1142-1144`), so a late answer to the abandoned REQ arrives under a
retired id, `route()` says `Retired` (`receipt.rs:184`) and it never reaches the
ledger (`relay.rs:1303`).

**Invariant:** an answer is never credited to a REQ sent after it
(`relay/receipt.rs:31-33`).

**Invariant:** a subscription that reuses an id replaces the old one on the
relay, so the post-AUTH replay at a full session is not refused by the relay's
cap (relay-event-admission diagram 4, `subscription_cap_reached`,
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:52-54`).

```mermaid
sequenceDiagram
    participant Page as Page or store
    participant RelayConn as RelayConnection
    participant Ledger as ReqLedger (receipt.rs)
    participant Relay as Relay

    Page->>RelayConn: subscribe_with_receipt(filters, on_event, on_receipt) (relay.rs:656, 665)
    RelayConn->>Ledger: sent(auth_accepted), outstanding 1 (relay.rs:681, receipt.rs:97)
    RelayConn->>Relay: REQ wire id sub_N (relay.rs:701-709)
    RelayConn->>RelayConn: arm_req_watch 8 s (relay.rs:696-698, 1101)
    alt answered in time
        Relay-->>RelayConn: EOSE sub_N (relay.rs:1290)
        RelayConn->>Ledger: answered(), authed only if all answered and the last REQ went out after AUTH (receipt.rs:109-116)
        RelayConn-->>Page: on_receipt(authed) (relay.rs:1310-1316)
    else no answer in 8 s
        RelayConn->>Ledger: on_watch(seq) (receipt.rs:131)
        alt Resend, at most 2 times
            RelayConn->>Relay: CLOSE sub_N then REQ sub_N~1 under a fresh wire id (relay.rs:1130-1144)
            Note over RelayConn: a late EOSE for sub_N is Retired and discarded (receipt.rs:184, relay.rs:1303)
        else GiveUp
            RelayConn->>RelayConn: warn and stop waiting (relay.rs:1118-1123)
        end
    end
```

---

## 7. Preview Worker and Search Worker (Brief Survey)

### Preview Worker (`crates/nostr-bbs-preview-worker/`)

```mermaid
sequenceDiagram
    participant Client as Forum Client<br/>(link_preview.rs component)
    participant PreviewWorker as Preview Worker<br/>(preview-worker/src/lib.rs)
    participant CFCache as Cloudflare Cache API
    participant External as External URL

    Client->>PreviewWorker: GET /preview?url=<target>
    PreviewWorker->>PreviewWorker: Rate limit: 30 req/60s per IP (lib.rs:517-519)
    PreviewWorker->>PreviewWorker: SSRF check: is_private_url() (ssrf.rs:277-288)
    PreviewWorker->>CFCache: get_from_cache(target_url) (lib.rs:156-160)
    alt Cache HIT
        CFCache-->>PreviewWorker: Cached JSON payload
        PreviewWorker-->>Client: 200 + {cached:true, X-Cache:HIT}
    else Cache MISS
        alt Twitter/X URL (oembed.rs:62-126)
            PreviewWorker->>External: fetch oEmbed API
        else OpenGraph
            PreviewWorker->>External: fetch HTML, parse OG tags (parse.rs:203)
        end
        External-->>PreviewWorker: Data
        PreviewWorker->>CFCache: put_to_cache(ttl: OG=10d, Twitter=1d)
        PreviewWorker-->>Client: 200 + {cached:false, X-Cache:MISS}
    end
```

### Search Worker (`crates/nostr-bbs-search-worker/`)

```mermaid
sequenceDiagram
    participant Client as Forum Client
    participant SearchWorker as Search Worker<br/>(search-worker/src/lib.rs)
    participant R2 as Cloudflare R2<br/>(RVF binary store)
    participant KV as Cloudflare KV<br/>(id↔label map)
    participant WorkersAI as Workers AI<br/>(bge-small-en-v1.5)

    Client->>SearchWorker: POST /search {query: "..."}
    SearchWorker->>WorkersAI: embed_texts(env, [query]) (embed.rs:61-82)
    Note over WorkersAI: Falls back to deterministic hash embedding<br/>when AI binding absent (embed.rs:69-82)
    WorkersAI-->>SearchWorker: 384-dim vector
    SearchWorker->>R2: load_store() — RVF binary (lib.rs:294-319)
    SearchWorker->>KV: load_mapping() — label↔id (lib.rs:363-414)
    SearchWorker->>SearchWorker: VectorStore::search(embedding, k, min_score)<br/>cosine k-NN (store.rs:52-82)
    SearchWorker-->>Client: [{id, score, distance}]

    Note over SearchWorker: Admin-only ingest (NIP-98 authed POST /ingest)
    Client->>SearchWorker: POST /ingest [{id, embedding}]<br/>Authorization: Nostr <nip98-token>
    SearchWorker->>SearchWorker: require_nip98_admin() (auth.rs:60-91)
    SearchWorker->>R2: persist_store() (RVF bytes)
    SearchWorker->>KV: persist id↔label mapping
```

---

The preview worker also serves `/ascii` (`lib.rs:351`), `/health` (`lib.rs:470`)
and `/stats` (`lib.rs:482`), routed at `lib.rs:532-544`. The search worker rate
limits `/search` to 100 requests per 60 s per IP (`lib.rs:927-936`), refuses a
query whose embedding model does not match the store (`lib.rs:495-500`) and may
rerank (`lib.rs:509-543`). `POST /ingest` takes entries of id, embedding, public
and optional snippet, plus an optional model (`handle_ingest`, `lib.rs:712-875`),
with the admin check at `lib.rs:720-730` and the store persisted at
`lib.rs:836-844`.

---

## 8. Incremental kind-5 deletion sync (PR #93)

Without a marker every session asked the relay for the newest 1,000 deletions,
most already applied. A device that has completed a deletion sync now asks only
for deletions at or after a per-device `since` marker
(`stores/deletion_sync.rs:1-12`). The relay keeps NIP-09 tombstones, hard-deletes
every ordinary target it honours and refuses to store it again
(relay-event-admission diagrams 2 and 10), so a target whose kind-5 is older than
the marker is not served back.

**What is persisted.** Per scope (channels, reactions) one `localStorage` record
`nostrbbs_deletion_sync_v3_channels` or `..._reactions`
(`DeletionScope::storage_key`, `deletion_sync.rs:151-161`) holding
`DeletionSyncState { since, sealed, held }` (`deletion_sync.rs:166-177`). Only the
tombstones that hide a **restored sealed original** (ADR-2017) are kept across
sessions, because the relay hard-deletes ordinary posts: `sealed` for resolved
ones (the deleter was honoured) and `held` for kind-5 targets not yet resolved
(`deletion_sync.rs:60-90`). Caps: 256 resolved and 64 held per deleter, 1,024
each overall, trimmed to a fair share (`deletion_sync.rs:126-132`, `fair_trim`
`208`, `enforce_caps` `230`). Reactions keep a marker but hold no tombstones
(test `reaction_progress_holds_no_tombstones`, `deletion_sync.rs:1190`).

**Tombstones are `(id, deleter)`, never the id alone** (`stores/tombstones.rs:1-31`).
`honoured` (`tombstones.rs:114`) decides per target kind: for an **ordinary** post
every deleter counts, since the relay's kind-5 gate is the authority there; for a
**restored sealed original** only the verified inner author, or a pubkey the relay
positively vouches is an admin (`GET /api/check-whitelist` `isAdmin`,
`stores/signer_admin.rs:108`, `parse_is_admin` `122-128`, fail closed), or the
reader's own local delete. A kind-5 that arrives before its target is held with
its deleter and judged when the target arrives, so arrival order changes nothing
(`tombstones.rs:22-26`). `admits` (`tombstones.rs:131`) is the single predicate
every insertion path asks (`channels.rs:267-299`).

**The marker only advances when a sync has settled**, and is
`min(newest kind-5 delivered, local now)` minus 14 days (`next_marker`,
`deletion_sync.rs:266`; `DELETION_SINCE_MARGIN_SECS`, `deletion_sync.rs:119`):
twice the relay's 7-day `created_at` drift allowance
(`RELAY_MAX_TIMESTAMP_DRIFT_SECS`, `deletion_sync.rs:110`, mirrors
`MAX_TIMESTAMP_DRIFT`, relay `nip_handlers.rs:44`), which kind 5 does not escape.
A marked sync that fills the 1,000-row page pages downwards with
`until = oldest delivered` (inclusive, `deletion_page_filter`,
`channels.rs:987`), at most 20 pages (`MAX_PAGES`, `deletion_sync.rs:123`,
`next_page` `424`, `first_step` `402`). An unmarked first sync takes the newest
1,000 and never pages.

```mermaid
sequenceDiagram
    participant CS as ChannelStore (channels.rs)
    participant DP as DeletionProgress (deletion_sync.rs)
    participant Relay as Relay
    participant TB as Tombstones (tombstones.rs)
    participant SA as SignerAdminCache (signer_admin.rs)
    participant LS as localStorage

    CS->>LS: load(Channels) since, sealed, held (channels.rs:134, deletion_sync.rs:614)
    CS->>TB: Tombstones::from_persisted(sealed, held) (channels.rs:135)
    CS->>Relay: REQ [kind 5 since marker limit 1000] among the channel filters (channels.rs:525-526, 974-981)
    loop each kind 5 delivered
        Relay-->>CS: EVENT kind 5 (channels.rs:453)
        CS->>DP: observe(created_at, deleter, targets, hold, Source::Main) (channels.rs:384-386, deletion_sync.rs:508)
        DP->>DP: newest_seen, count the row, record_held per deleter (deletion_sync.rs:517-536, 283)
        CS->>TB: apply_deletion: fold_deletion per target (channels.rs:194-213, tombstones.rs:164)
        opt a sealed original named by a deleter that is not its author
            CS->>SA: request(deleter) (channels.rs:209-211)
            SA->>Relay: GET /api/check-whitelist?pubkey= (signer_admin.rs:108)
            Relay-->>SA: isAdmin, a definite answer or none (signer_admin.rs:122-128)
            SA-->>CS: prune_on_admin_answers re-judges held tombstones (channels.rs:164-188)
        end
    end
    Relay-->>CS: EOSE
    CS->>DP: on_main_eose (channels.rs:509-512, deletion_sync.rs:570)
    alt marked backfill delivered a full page
        DP-->>CS: Fetch until = oldest delivered, page 1 (deletion_sync.rs:402-407, 572-575)
        loop at most 20 pages
            CS->>Relay: REQ [kind 5 since marker until U limit 1000] (deletion_sync.rs:653-681, channels.rs:987)
            Relay-->>CS: EVENT kind 5 rows, Source::Page(n) (deletion_sync.rs:657-661)
            Relay-->>CS: EOSE, on_page_eose then next_page (deletion_sync.rs:589-601, 424-439)
        end
        Note over DP: GiveUp when a page is empty, a full page makes no progress, or 20 pages are done: the old marker stays (deletion_sync.rs:425-437, 553)
        Note over DP: OPEN (O23): nothing records how far paging got, so the next session restarts from the old marker (deletion_sync.rs:30-34)
    else short or unmarked
        DP-->>CS: Done, settle(true) advances the marker (deletion_sync.rs:539-547)
    end
    DP->>LS: persist(Channels) (deletion_sync.rs:628-633)
```

**Invariant:** a kind-5 accepted by the relay after a marker-advancing sync is at
or above that marker, so the next sync fetches it (`deletion_sync.rs:54-59`).

**Open (O23):** when paging gives up (20 pages, an empty page, or a full page
with every row at one `created_at`) the marker is not moved and the next session
starts again from the same `since` with no resume cursor
(`deletion_sync.rs:30-34`). A device more than 20,000 deletions behind therefore
re-fetches the same pages every session.

**Open (O25):** the client can vouch for an admin but not for a TL3 moderator
(`tombstones.rs:12-18`): a TL3's kind-5 of a sealed original does not hide it on
other clients, and is instead made real on the relay by removing the envelope
(relay-event-admission diagram 10). Separately, the `isAdmin` it asks for comes
from `check-whitelist`, which reads only `whitelist.is_admin`
(`crates/nostr-bbs-relay-worker/src/whitelist.rs:135-142`, `isAdmin` in the reply
at `whitelist.rs:180`), whereas the relay's own admin test also honours the static
`ADMIN_PUBKEYS` set (`relay-worker/src/auth.rs:181-191`). An admin that exists
only in `ADMIN_PUBKEYS` is an admin to the relay but is "not an admin" to the
client, so that admin's deletion of a sealed original is not honoured by clients.

---

## 9. Page lookup state: loading, found, not found, timed out (PR #91)

A cold deep link used to show "Topic Not Found" as soon as `ChannelStore::loading`
cleared, which says nothing about whether the kind-42 history had been requested
(`utils/lookup.rs:1-9`). The zone, section and topic pages now decide with
`Lookup::decide(found, synced, deadline_passed)` (`lookup.rs:91-102`):
presence beats everything, a receipt beats the clock, and only then the 15 s
deadline (`LOOKUP_DEADLINE_MS`, `lookup.rs:37`) gives `TimedOut`, reported
separately from `NotFound` so the page does not claim an absence it has not
observed (`lookup.rs:73-85`). `Lookup::then` chains a nested lookup: a topic is
looked up only once its section was found (`lookup.rs:106-111`).

"Synced" is a `SyncReceipt` (`lookup.rs:41-66`): `any` once any EOSE arrived,
`authed` once an EOSE was an *authenticated* answer, per the relay layer's REQ
ledger (section 6). `settles(zone_gated)` needs `authed` for a zone that is not
public, because the pre-AUTH answer omits members-only events by design
(`lookup.rs:62-68`), and `zone_is_gated` (`lookup.rs:123`) says which. The deadline
is a `DeadlineClock` re-armed per target, since Leptos reuses a route component
when only its params change (`DeadlineClock` `lookup.rs:150`, `deadline_for` `191`). The
receipts live in the store: `channel_receipt` (`channels.rs:90`, recorded at
`503`) and one per channel history (`history_receipts`, `channels.rs:96`, recorded
at `759-762`, read by `history_receipt` `682`).

```mermaid
flowchart TD
    URL([deep link /forums/zone/section/topic])
    Z{zone page: sections found?<br/>Lookup.decide<br/>pages/category.rs:140-158}
    S{section page: channel found?<br/>channel_receipt settles?<br/>pages/section.rs:302-312}
    SH{history receipt settles?<br/>pages/section.rs:313-322}
    T{thread page: channel, then topic root found?<br/>pages/thread.rs:637-655}
    LOAD([Loading: spinner<br/>pages/thread.rs:1174-1181])
    FOUND([Found: render])
    NF([NotFound: Topic Not Found<br/>pages/thread.rs:1183-1186])
    TO([TimedOut: Topic Unavailable<br/>pages/thread.rs:1187-1190])
    REC[SyncReceipt.settles zone_gated:<br/>public zone: any EOSE<br/>gated zone: authenticated EOSE<br/>utils/lookup.rs:62-68]
    DL[deadline 15 s, re-armed per target<br/>utils/lookup.rs:37, 150, 191]

    URL --> Z
    URL --> S
    S --> SH
    URL --> T
    T -->|found| FOUND
    T -->|absent and receipt settles| NF
    T -->|absent, no receipt, deadline passed| TO
    T -->|absent, no receipt, deadline not passed| LOAD
    REC -.-> T
    DL -.-> T
```

**Open (O21):** in an encrypted zone a cold deep link can still show "Topic Not
Found" between the authenticated answer and the arrival of the zone keys
(observed live on 2026-11-22, about 12 s to 29 s, after which it corrected
itself; a fix is in progress). What the code shows: the topic root is looked up
by event id among the channel's stored kind-42 events (`pages/thread.rs:485-506`);
a zone-encrypted message without its key is stored as a placeholder that keeps
its own id, tags and signature (`zone_crypto/store.rs:407-412`), so an ordinary
encrypted topic root should be found. The path to `NotFound` is read from the
code only for a **sealed migrated original**, which lives inside an envelope with
a different id until the key opens it and `redecrypt` replaces it under the
original id (`zone_crypto/store.rs:450`, `1202-1206`); the lookup has no input
for "keys not loaded yet" (`pages/thread.rs:637-655`, `utils/lookup.rs:91-102`).
So for such a topic, once the authenticated history receipt has arrived
(`channels.rs:759-762`) and before `redecrypt`, `topic_root` is `None`, the
receipt settles, and `Lookup::NotFound` renders (`pages/thread.rs:1183-1186`).
Whether the observed cases were all migrated topics, or whether another path
exists for ordinary encrypted topics, is not established. The timing is the observation; the
mechanism above is read from the code and was not reproduced.

---

## 10. Zone keys per signed-in identity (PR #92)

Zone keys are cached in IndexedDB, which every account on one browser profile
shares. Since #92 each row carries its owner in an `owner` field **and** in its
id, `"<owner pubkey>/<store id>"` (`zone_crypto/key_owner.rs:1-26`,
`owned_row_id` `key_owner.rs:69`, `StoredZoneKey::owned` `stores/indexed_db.rs:104`),
so two identities' rows never share an id and one cannot overwrite the other's.
The only key-write API takes an `Owner` (a validated 64-hex newtype,
`key_owner.rs:38-49`): `put_zone_key_unless_conflicting` (`indexed_db.rs:443`) and
`put_minted_zone_key` (`indexed_db.rs:466`).

**What an identity sees.** Its own rows, plus the legacy rows, minus any legacy
row it has its own row for (`visible_keys`, `key_owner.rs:172`, `slot_view`
`key_owner.rs:88`). A legacy row (no owner) cannot be attributed, so it stays,
is never written or deleted, and is seen by every signed-in identity on the
device and by nobody while signed out (`key_owner.rs:13-19`).

**The identity switch.** `provide_zone_key_store` follows auth
(`zone_crypto/store.rs:1162-1171`): the owner is set only while authenticated
(`owner_from_auth`, `key_owner.rs:60`), so a restored but locked session loads no
keys. On any change `switch_owner` (`store.rs:187`) drops the previous identity's
keys, conflicts, inbox key, grant subscriptions and held group signers, re-runs
decryption with no keys so plaintext goes back to placeholders
(`store.rs:187-206`), and loads the new identity's view under a fresh `Lease`
(`load_for` `store.rs:490`, `load_stored` `497`). Work for an earlier identity
still stores under its own owner but touches memory, the relay and the UI only
while its lease is current (`key_owner.rs:280-330`, `store.rs:799-847`).
Readiness is per owner (`ready_for`, `store.rs:153`), so the Encryption card
offers Create or Rotate only once the signed-in identity's keys are loaded
(`admin/zone_encryption.rs:192`).

**Other per-identity state.** Bookmarks are stored under
`nostrbbs_bookmarks:v2:<pubkey>` (or `anon` while signed out or locked) and keep
no text preview for an encrypted-zone message
(`components/bookmarks_modal.rs:1-15`, `bookmarks_key` `38-41`,
`bookmark_preview` `44`); drafts under `draft:v2:<pubkey>:<channel>`, with the
pre-owner `draft:<channel>` keys deleted once at start-up
(`components/draft_indicator.rs:44-54`, `drop_legacy_drafts` `84`); notifications
for an encrypted zone read "New encrypted message in <channel>" with no preview
and no author (`stores/notifications.rs`, see the PR #92 description). This is
isolation between accounts in the forum's UI, not access control: same-origin
storage is readable by any script on the origin or anyone with the device
(`key_owner.rs:21-24`).

**Open (O24):** keys written before #92 (legacy rows) and bookmarks saved before
it (the browser-wide `nostrbbs_bookmarks` key) cannot be attributed, so they stay
visible to every account that signs in on that browser
(`zone_crypto/key_owner.rs:13-19`, `components/bookmarks_modal.rs:1-15`);
removing a legacy bookmark removes it for all. Isolation covers keys received or
created from #92 on, and legacy previews are erased at start-up rather than the
bookmarks. (Pre-owner drafts, by contrast, are deleted outright,
`draft_indicator.rs:84`.)

```mermaid
flowchart TD
    AUTH([auth state changes])
    OWNER{authenticated with a 64-hex pubkey?<br/>key_owner.rs:60}
    NONE[no owner: keys dropped,<br/>plaintext back to placeholders<br/>store.rs:187-206]
    SWITCH[switch_owner: new Lease,<br/>clear keys, conflicts, inbox key,<br/>grant subscriptions, group signers<br/>store.rs:187-206]
    LOAD[load_stored: migrate rows,<br/>read all rows, device epoch floor<br/>store.rs:497-530]
    VIEW[visible_keys: own rows,<br/>then legacy rows for slots without one<br/>key_owner.rs:172]
    READY([loaded_for = owner, ready_for true<br/>store.rs:493, 153])
    CARD[Encryption card may offer Create or Rotate<br/>admin/zone_encryption.rs:192]
    LEG[legacy rows: read-only, shown to every identity,<br/>never written or deleted<br/>key_owner.rs:13-19]

    AUTH --> OWNER
    OWNER -->|no| NONE
    OWNER -->|yes| SWITCH
    SWITCH --> LOAD --> VIEW --> READY --> CARD
    LEG -.-> VIEW
```

---

## 11. Minting, rotating and receiving keys: the epoch guards (PRs #83, #84, #87, #92)

Four guards stop two different keys ever sharing one `(zone, epoch)` or a key
being used before it reaches its members.

1. **Pending delivery (#83).** A key this device created is stored with
   `pending_delivery = true` (`zone_crypto/mod.rs:165-171`, set by the card at
   `admin/zone_encryption.rs:486-491`). It decrypts but is never chosen to send
   under: `send_key` (`keyset.rs:70`) drops any key pending in any row for that
   `(epoch, pubkey)` (`keyset.rs:78-95`), so a rotation whose grants fail cannot
   leave new posts readable only on this device. `mark_delivered`
   (`store.rs:343`) clears it once the relay has accepted the grants, and an echo
   cannot re-pend it (`store.rs:851-884`, `keep_pending` `323`).
2. **No second key for an epoch in use (#84).** `conflicts` (`zone_crypto/mod.rs:176`)
   says a different secret or pubkey for the same store id is a conflicting mint,
   never an update. Every key write is guarded: `put_decision`
   (`key_owner.rs:105`) over the identity's view (the legacy row counts),
   `insert_persisted` (`store.rs:799-889`, a conflict is recorded and the grant
   settled, `store.rs:816-826`) and `insert_local` (`store.rs:898-925`).
3. **Memory adopts storage on a conflict (#87).** If storage accepted a key but
   memory holds another (another tab's write), `adopt_stored` (`store.rs:272`,
   called at `store.rs:859`) makes memory match storage, never the reverse.
4. **Mint plan (#87, #92).** `plan_mint` (`keyset.rs:169`) returns `Wait` until the
   message sync has finished (`ready = msg_eose_received && keys_ready`,
   `admin/zone_encryption.rs:199-225`), `Blocked(reason)` for a keyless identity
   whose only evidence is a far-ahead epoch, or `Mint { epoch, note, higher_seen }`
   (`keyset.rs:129-153`). The epoch is above the identity's own latest, above every
   believable epoch named by a post, and above every epoch any row on the browser
   holds for the zone under any owner (`device_epochs_for`, `store.rs:161`; epoch
   numbers only). Neither a post nor another account's row is believed beyond
   `MAX_EPOCH_SKIP = 8` of what the identity can vouch for (`keyset.rs:125`,
   `plan_mint` `169-258`). A mint below an epoch seen in posts asks for explicit
   confirmation (`mint_confirmation` `keyset.rs:271`, card
   `admin/zone_encryption.rs:444-447`). The write re-checks in its own transaction
   (`put_minted_zone_key`, `indexed_db.rs:466`, `mint_decision`
   `key_owner.rs:131`), refusing a different key at or above the mint epoch held
   by the identity itself, or by another account within `MAX_EPOCH_SKIP`.

```mermaid
flowchart TD
    CARD([admin presses Create or Rotate<br/>admin/zone_encryption.rs:433])
    PLAN{plan_mint<br/>keyset.rs:169}
    WAIT([Wait: message sync not finished<br/>or keys not loaded<br/>keyset.rs:175-177])
    BLOCK([Blocked: no key held and only<br/>far-ahead epochs seen<br/>keyset.rs:213-230])
    MINT[Mint epoch above own latest,<br/>post epochs and device epochs<br/>keyset.rs:230-258]
    CONF{epoch below one seen in posts?<br/>mint_confirmation keyset.rs:271}
    ASK[confirm dialog<br/>admin/zone_encryption.rs:444-452]
    LOCAL[insert_local: slot guard then<br/>put_minted_zone_key in one transaction<br/>store.rs:898-925, indexed_db.rs:466]
    REFUSED([refused: different key held<br/>store.rs:917-921])
    PEND[stored pending_delivery true,<br/>never the send key<br/>keyset.rs:78-95]
    GRANT[grants sent to members and the creator<br/>admin/zone_encryption.rs:492-495]
    DELIV[mark_delivered clears the flag<br/>store.rs:343]
    SEND([key becomes the send key<br/>keyset.rs:70])

    CARD --> PLAN
    PLAN -->|Wait| WAIT
    PLAN -->|Blocked| BLOCK
    PLAN -->|Mint| MINT
    MINT --> CONF
    CONF -->|yes| ASK
    CONF -->|no| LOCAL
    ASK -->|confirmed| LOCAL
    LOCAL -->|conflict or superseded| REFUSED
    LOCAL -->|stored| PEND
    PEND --> GRANT --> DELIV --> SEND
```

---

## Findings

Status at `3c48e26`. F-01 to F-12 keep their June numbering; F-13 onwards are new.

### F-01 — MEDIUM | `provision_pod` duplicated across modules — still holds, worse

**Files:** `pages/signup.rs:170-204`, `pages/settings.rs:2017-2052`,
`utils/pod_client.rs:46-78`

There are now three near-identical copies: signup, settings and the
self-healing `provision_pod_signer` in `utils/pod_client.rs`. The settings copy
(called at `pages/settings.rs:659`, now also on a 403) is redundant with
`utils/pod_client.rs:21-44`. **Classification:** Code duplication / maintenance
risk. (Register O8.)

---

### F-02 — MEDIUM | `qr_svg` duplicated: `recovery_sheet.rs` and `devices.rs` — still holds

**Files:** `components/recovery_sheet.rs:60-75`, `utils/devices.rs:241-259`

Identical `qr_svg(data: &str) -> String` using the same `qrcode` path. The
`recovery_sheet.rs` import at line 59 takes other `devices` symbols but not
`qr_svg`. **Classification:** Code duplication.

---

### F-03 — RESOLVED | `NIP05_USERNAME_HOST` hardcoded to `"example.test"` in `settings.rs`

~~`pages/settings.rs:30` hardcoded the host.~~ `settings.rs` now imports
`NIP05_HOST` from `components/onboarding_modal.rs` (`pages/settings.rs:35`), which
bakes it from `option_env!("NOSTR_BBS_NIP05_DOMAIN")`
(`components/onboarding_modal.rs:59-62`); a test asserts the two agree
(`pages/settings.rs:2411-2416`). `"example.test"` remains only as the
unconfigured-build fallback (`onboarding_modal.rs:61`). Signup no longer handles a
NIP-05 name at all. (Register O7.)

---

### F-04 — LOW | `/chat` route redirects to `/forums`; `ChatPage` is gone — amended

`/chat` still redirects to `/forums` (`app.rs:977`) and `/chat/:channel_id` still
routes to `AuthGatedChannel` (`app.rs:978`). `ChatPage` and `pages/chat.rs` no
longer exist, so the June claim that `ChatPage` remains reachable is stale; what
remains is `/chat/:channel_id` serving `ChannelPage`. **Classification:**
legacy URL alias.

---

### F-05 — MEDIUM | Two kind-42 subscriptions write one store — still holds, reshaped

`start_msg_sync` (`stores/channels.rs:560`) and `ensure_subscribed`
(`channels.rs:693`) both feed `channel_messages` through `admits_message` and
`insert_message` (`channels.rs:580-629`, `720-745`, `807`), which dedups. The
broad subscription is no longer a single unfiltered REQ: `message_sync_filters`
(`channels.rs:1042`) builds per-zone `#e` filters plus a broad catch-all (#81).
**Classification:** overlapping state authority / redundant relay traffic.

---

### F-06 — RESOLVED | DM subscriptions silently no-op for NIP-07 users

See section 5. `subscribe_incoming` (`dm/mod.rs:320-368`) takes a `Signer` with no
raw-key early return, and an extension without NIP-44 gets a state error
(`dm/mod.rs:1253-1264`) and a banner (`pages/dm_list.rs:295-296`, `334-345`).
(Register O6.)

---

### F-07 — MEDIUM | `DEVICE_KEYS_ENABLED` has no client-side deployment source — partly holds

**Files:** `utils/devices.rs:88-114`, `components/recovery_sheet.rs:360`,
`pages/settings.rs:148`

The flag is documented at `SETUP.md:171-174`, `docs/architecture.md:477` and
ADR-2004, but the client crate still has no `index.html`, `Trunk.toml` or script
that injects `window.__ENV__.DEVICE_KEYS_ENABLED`; only the docs describe the
client side. **Classification:** feature gate the UI reads with no in-crate source.

---

### F-08 — LOW | Relay URL read in two places with different fallbacks — still holds

**Files:** `relay.rs:1534-1553` (const `DEFAULT_RELAY_URL`, `relay.rs:29-30`),
`utils/relay_url.rs:7-15`, `relay_api_base` `utils/relay_url.rs:20-33`

`relay.rs` falls back to `wss://relay.example.com`; `relay_url.rs:13` falls back
to a different, real worker URL, and `relay_api_base` repeats it a third time.
**Classification:** duplicated relay-connection logic with diverging fallbacks.
(Register O8.)

---

### F-09 — LOW | Three manual auth gates beside the `auth_gated!` macro — smaller

`AuthGatedChannel` (`app.rs:1469-1494`), `AuthGatedDmList` (`1496-1521`) and
`AuthGatedDmChat` (`1523-1548`) are written out by hand; the macro is at
`app.rs:1565-1594` with its invocations at `1596-1608`. `AuthGatedChat` is gone.

---

### F-10 — RESOLVED | `onboarding_modal` imported in `settings.rs` but not rendered there

`pages/settings.rs:18-21` no longer imports `open_onboarding_with_prefill`, and
`OnboardingModal` is recorded as a removed dead component
(`components/onboarding_modal.rs:187-191`).

---

### F-11 — MEDIUM | NIP-49 `ncryptsec` still deferred; 0xchat confusion risk — still holds

`recovery_sheet.rs:46-50` records NIP-49 as deferred and `nostr-bbs-core/src` has
no NIP-49 support; the 0xchat "Login with QR" warning is at
`recovery_sheet.rs:469-472`. Correction: the download HTML has four sections, not
three.

---

### F-12 — AMENDED | `settings.rs` kind-0 subscription

`pages/settings.rs` still opens a `{authors:[pk], limit:1}` kind-0 subscription
each time its effect runs (`settings.rs:387-498`, subscribe `457-473`). It no
longer auto-unsubscribes after 5 s: it closes in `on_cleanup`
(`settings.rs:479`), and the 5 s timer only sets a `profile_load_slow` flag
(`settings.rs:488-497`). The app-root kind-0 subscription is unfiltered with
limit 500 (`app.rs:773-777`), so the redundancy point stands.

---

Written records of F-13 to F-18: KF-23, KF-24, KF-25, KF-26, KF-27, KF-28 in
`docs/security/known-findings.md`.

### F-13 — MEDIUM | Cold deep link in an encrypted zone can show "Topic Not Found" (O21)

Section 9. Topic lookup has no input for "zone keys not yet loaded".

### F-14 — MEDIUM | A post made while the socket is closed is flushed before AUTH (O22)

`send_or_defer_write` defers a write only while the socket is **open** and
unauthenticated (`relay.rs:772-781`). With the socket closed it goes straight to
`pending_messages` (`relay.rs:815-826`), and `onopen` drains those non-REQ frames
into the paced send queue (`relay.rs:511-517`, `535-537`) **before** the AUTH
challenge has been answered. In `nip42` mode the relay refuses such an EVENT with
`auth-required:` (relay-event-admission diagram 2, `nip_handlers.rs:1142`); the
publish callback then shows the explanation (`relay.rs:1414-1420`) only if an
`auth_note` exists, which it does not yet at that point. **Classification:** a
race the held-writes mechanism does not cover.

### F-15 — LOW | Deletion paging has no resume cursor when it gives up (O23)

Section 8.

### F-16 — MEDIUM | Legacy zone-key and bookmark rows are shared across accounts (O24)

Section 10.

### F-17 — MEDIUM | The client can identify admins but not TL3 moderators, and `isAdmin` omits static admins (O25)

Section 8.

### F-18 — LOW | Pod Browser's mesh card prints a raw error under "Details" (O26)

`pages/pod_browser.rs:1045-1061`: on a native-pod probe error the card renders
the error string `e` verbatim inside `<details>` (`detail = e.clone()`,
`pod_browser.rs:1049`, rendered at `1058-1059`); the personal-pod card does the
same (`pod_browser.rs:1172-1181`). `e` is the string error from the probe
(`pod_browser.rs:602`, `660`). Whether that string is a stack trace depends on
the failing call, and cannot be established from the code alone; it is not
sanitised either way.

---

*Verified against `origin/main` `3c48e26` on 2026-11-22. All file:line references
are to `crates/nostr-bbs-forum-client/src/` unless otherwise noted.*
