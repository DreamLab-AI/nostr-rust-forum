# nostr-rust-forum — Closeout Security Audit Register

**Date:** 2026-07-03  
**Method:** Fable-orchestrated Opus ruflo mesh — 9 comparison dimensions, each analysed by an Opus agent and adversarially verified by a second Opus agent (39 CONFIRMED / 6 ADJUSTED / **0 REFUTED** + 20 verifier-surfaced misses). Fable confined to orchestration + synthesis; all analysis and remediation by Opus agents.  
**Consumes:** `solid-pod-rs = 0.5.0-alpha.3` (crates.io, `core` feature) — several findings are consumption-boundary issues inherited from the pinned (pre-closeout-fix) version.

## Severity tally (verified, non-refuted)

| Severity | Count |
|----------|-------|
| **P0** | 2 |
| **P1** | 9 |
| **P2** | 30 |
| **P3** | 37 |
| verifier-surfaced misses | 20 |


## P0

### (clients-mesh) Forum client renders relay events with NO signature or event-id verification (systemic authorship forgery)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/relay.rs:560-597 (EVENT branch: serde_json::from_value then cb(event), no verify); contrast crates/nostr-bbs-bbs-client/src/relay.rs:475; capability exists at crates/nostr-bbs-core/src/event.rs:205 (verify_event_strict)
- **Detail:** handle_relay_message's EVENT branch deserializes a NostrEvent and dispatches it straight to subscription callbacks, deduping only on the UNVERIFIED event.id. It never recomputes the id from the canonical serialization and never checks the Schnorr signature, even though core exposes verify_event_strict (crates/nostr-bbs-core/src/event.rs:205) and the sibling bbs-client DOES verify before ingesting
- **Decision:** FIX — call nostr_bbs_core::verify_event_strict(&event) in forum-client relay.rs before dedup/dispatch (mirror bbs-client:475); drop on failure. Blocks authorship/profile/moderation spoofing across single-relay and mesh.

### (preview-search-ascii) Stored XSS at ASCII consumption boundary: bbs-client inner_html's text/html from any host that prefix-matches pod_api  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-bbs-client/src/ascii_img.rs:107-109 (is_pod_url prefix match), :156-158 (format=ascii appended to attacker src), :277 (only text/html check), :99-101 (inner_html=html); trigger via is_image_url crates/nostr-bbs-bbs-client/src/ascii_img.rs:181-187; ASCII crate escaper it bypasses at crates/nostr-bbs-ascii/src/lib.rs:189-197
- **Detail:** The ASCII crate's security contract is 'output is our own worker HTML, already escaped, safe to inject'. The bbs-client breaks that contract. is_pod_url() classifies a src as pod-hosted with a bare `src.starts_with(pod_api)` string prefix (no authority/label boundary). An attacker posts an image URL such as https://pods.example.com.evil.com/x.png : it passes is_image_url (ends .png, http scheme) a
- **Decision:** FIX — replace the prefix check with a parsed-URL exact host/authority match (Url::parse then compare host_str to pod_api's host), or route all non-first-party images through the preview /ascii endpoint (whose output is escaped) and never in


## P1

### (auth-worker) WebAuthn registration binds an arbitrary attacker-chosen Nostr pubkey to a passkey with no proof-of-control (forged identity)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-auth-worker/src/webauthn.rs:835-838 (pubkey taken from body, only shape-validated), :970-978 (sole guard is existing-row 409), :1041-1048 (returns verified:true + didNostr with no NIP-98); consumed at crates/nostr-bbs-auth-worker/src/did.rs:27-29 (DID existence gated only on webauthn_credentials row)
- **Detail:** register_verify accepts body.pubkey as the account identity and stores the passkey↔pubkey binding after only verifying the WebAuthn attestation (proof the caller holds SOME passkey). It never verifies that the passkey's PRF output actually derives body.pubkey, and requires no NIP-98/Nostr signature proving control of that pubkey — the whole security model ('passkey PRF derives the nsec') is assert
- **Decision:** FINISH — require, inside register_verify, a NIP-98 (or a Nostr Schnorr signature over the WebAuthn challenge/credential_id) proving control of body.pubkey before inserting the credential row; reject otherwise. This closes the squatting/DoS,
- **Device-key analogue (RESOLVED 2026-07-19):** The same proof-of-control class of bug existed on the device-key registration path (`crates/nostr-bbs-auth-worker/src/devices.rs` `handle_register`): `device_pubkey` was an arbitrary caller-supplied 64-hex value upserted with no proof the caller controlled it and no check it wasn't already a principal, so a member could register `device_pubkey = <admin hex>` and — via the relay's `effective_pubkey()` device→owner rebind — silently hijack the admin's write-allowlist + read-scope (admin lockout / cross-account identity hijack). **Fixed** with two guards: (1) **proof-of-possession** — registration now requires a `device_proof`, a device-key-signed event (kind 27236) committing to `(owner_pubkey, exp)`, verified server-side with the crate's canonical `verify_event_strict` Schnorr primitive (`verify_device_proof`); an attacker cannot forge a proof for a key they don't hold, and the owner-tag binding blocks cross-owner replay; (2) **principal exclusion** — a `device_pubkey` that is itself a registered principal (whitelist member, admin set, or existing device owner) is rejected (`is_known_principal`, HTTP 409). Gated behind `DEVICE_KEYS_ENABLED` but hardened before republish. Covered by `devices::tests::device_proof_*`.

### (clients-mesh) Content parsers use char-count as byte index → crafted post reliably panics every viewer (stored DoS)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/components/mention_text.rs:215 (`&after_nostr[..npub_len]`), :217 (`remaining[pos + 6 + npub_len..]`), :286 (`&input[i + 1..i + 65]`); called from message_bubble.rs:215 on raw content
- **Detail:** MentionText.parse_mentions computes npub_len as a COUNT of is_alphanumeric() chars (which returns true for many multibyte Unicode letters/digits) and then byte-slices with it: `&after_nostr[..npub_len]` and `&remaining[pos + 6 + npub_len..]`. Input as trivial as the literal string `nostr:npub1é` makes npub_len=6 while the byte length is 7, so the slice lands mid-UTF-8-char and panics. find_next_at
- **Decision:** FIX — parse over char_indices()/byte offsets or restrict the accepted set to ASCII [a-z0-9] (bech32 is ASCII) before slicing; add a multibyte-content unit test. Removes the trivial stored-DoS.

### (config-setup-canary) Config validation is never invoked at runtime — every security check is dead defense  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/src/lib.rs:5-7 (startup claim); crates/nostr-bbs-config/src/validate.rs:6; grep of load_from_str|load_from_path|validate_config across crates/ excluding nostr-bbs-config = 0 hits
- **Detail:** lib.rs and README assert 'Worker crates in the nostr-bbs-*-worker set load this at startup', but no worker (auth/pod/preview/relay/search) calls nostr_bbs_config::load_from_str / load_from_path / validate_config. A workspace-wide grep returns ZERO callers outside the config crate's own tests/doctest. The relay-worker, forum-client and bbs-client only re-declare the Zone serde shape (or take the ty
- **Decision:** FINISH — call load_from_path+validate_config in each worker's startup (or a build.rs gate), OR FREEZE and relabel the crate as build-time schema only so operators aren't misled that validation runs.

### (core-protocol) NIP-59 unwrap never verifies the seal signature nor binds rumor.pubkey == seal.pubkey (attacker-controllable author)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/src/gift_wrap.rs:307-358 (unwrap_gift: seal parsed at 325-334, no verify_event, no pubkey binding) and 444-485 (unwrap_gift_with_signer, same); UnwrappedGift shape at 77-85; consumer forum-client/src/dm/mod.rs:635-651 trusts rumor 'p' tag / sender_pubkey
- **Detail:** unwrap_gift and unwrap_gift_with_signer decrypt gift->seal->rumor, check only the three kind fields (1059/13/14), and return UnwrappedGift{ sender_pubkey = seal.pubkey, rumor, seal } WITHOUT (a) calling verify_event on the seal (kind 13) and (b) asserting rumor.pubkey == seal.pubkey. NIP-59 mandates both: the seal MUST be signature-verified and the inner rumor's pubkey MUST equal the seal's pubkey
- **Decision:** FIX — after decrypting the seal, call verify_event_strict(&seal) and reject unless rumor.pubkey == seal.pubkey; only then set sender_pubkey. Cheap, in-crate, restores NIP-59 authentication guarantee.

### (core-protocol) validate_moderation_event authorises on event.pubkey with no signature/id verification (auth footgun; auth-worker does not verify)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/src/moderation_events.rs:154-256 (admin check at 249-253 keyed on event.pubkey; contract prose at 16-18); consumer crates/nostr-bbs-auth-worker/src/moderation.rs:216-220 (validate_moderation_event with no verify_event, no event.pubkey==admin_pubkey binding)
- **Detail:** validate_moderation_event gates admin-only kinds via admin_set.contains(&event.pubkey) and binds the d-tag admin half to event.pubkey, but never verifies the event's Schnorr signature or recomputes its id. Its only safety contract is prose ('the relay + auth-worker are expected to reject publication from non-admin signers') at the module head. The auth-worker consumer handle_action does NOT verify
- **Decision:** FIX — make validate_moderation_event require a verified event (take a Verified<NostrEvent> newtype or verify_event_strict internally) and have handle_action assert body.event.pubkey == authenticated admin_pubkey; do not rely on prose.

### (pod-worker) Public-TypeIndex ACL accessTo lacks leading slash → dead public-read carve-out AND owner lockout on publicTypeIndex.jsonld  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/provision.rs:26 (const, no leading slash), provision.rs:61-89 (render_public_type_index_acl uses PUBLIC_TYPE_INDEX_PATH as accessTo at lines 72 and 83), provision.rs:386-397 (ACL written to R2); contrast solid-pod-rs alpha.3 src/provision.rs:119 (upstream = "/settings/publicTypeIndex.jsonld"); path-match logic .cargo/registry/.../solid-pod-rs-0.5.0-alpha.3/src/wac/evaluator.rs:63-106
- **Detail:** provision.rs defines `PUBLIC_TYPE_INDEX_PATH = "settings/publicTypeIndex.jsonld"` WITHOUT a leading slash and uses that constant verbatim as the `acl:accessTo` @id for both the owner and the foaf:Agent grant in render_public_type_index_acl. The upstream solid-pod-rs constant it claims to mirror is `"/settings/publicTypeIndex.jsonld"` WITH a leading slash (used as the absolute resource IRI). The po
- **Decision:** FIX — use a leading-slash form for the ACL accessTo (e.g. `format!("/{PUBLIC_TYPE_INDEX_PATH}")`) so it matches the evaluator's resource paths; add a regression test that evaluates the provisioned ACL against the real `/settings/publicTypeI

### (relay-ratelimit) REQ and COUNT are entirely unrate-limited (and unauthenticated), enabling D1 read amplification DoS  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:141 (only check_rate_limit call site); handle_req nip_handlers.rs:553 (no limiter); handle_count nip_handlers.rs:1015 (no limiter, full-row fetch); per-filter D1 loop storage.rs:250; NIP-50 leading-wildcard LIKE filter.rs:174-182; per-event gate D1 lookups nip_handlers.rs:972-995
- **Detail:** The per-IP flood limiter self.check_rate_limit(ip) is called ONLY in handle_event (EVENT path). handle_req and handle_count call no limiter at all, and neither requires authentication (only kind-1059 filters need auth). Every REQ/COUNT can carry up to MAX_FILTERS=10 filters, and query_events runs one D1 query PER filter (each up to LIMIT 1000). A NIP-50 `search` filter compiles to `content LIKE '%
- **Decision:** FIX — add a per-IP (and ideally per-connection) REQ/COUNT rate limiter, cap total rows scanned per frame, make COUNT use SQL COUNT(*) with the gate pushed into SQL or reject unauthenticated COUNT on gated kinds, and require a minimum filter

### (relay-ratelimit) No event retention/pruning — unbounded D1 storage; NIP-11 advertised retention is false  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/nip11.rs:71-79 (retention block); cron.rs (only backfill_profiles + sweep_inactive_demotions, no event DELETE); storage.rs:288-295 (expired events skipped on read, never deleted); repo-wide grep: no retention/NIP-40 DELETE FROM events exists
- **Detail:** NIP-11 advertises time-based retention (kind-1: 7776000s/90d, kind-7: 2592000s/30d, kind-9024: 86400s/1d, others null). No code enforces it. The scheduled/cron handler only runs profile backfill and the trust-demotion sweep — there is no DELETE of retention-expired or NIP-40-expired events anywhere. NIP-40-expired events are merely skipped at read time in query_events (storage.rs:288) but remain i
- **Decision:** FIX — add a paged, bounded retention/expiry sweep to the scheduled handler (delete rows past their kind's retention window and past NIP-40 `expiration`), OR FREEZE by removing the retention claims from NIP-11 until implemented; unbounded st

### (stubs-adrs) ADR-124 and ADR-125 govern shipped security-load-bearing code but have no decision record anywhere in docs/  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-pod-worker/src/pod_git_anchor.rs:1,16-33; crates/nostr-bbs-pod-worker/src/provision.rs:107-115; docs/adr/README.md:register-ends-at-105
- **Detail:** The native pod-git identity trail (agent.did.json Multikey DID doc, git config nostr.privkey, gitmark.json/blocktrails.json single-use-seal chain) and its I1-I4 auth invariants are governed entirely by ADR-124 and ADR-125, cited 21 and 20 times across 9 source files (core/did.rs, pod-worker did.rs/lib.rs/provision.rs/pod_git_anchor.rs/contexts.rs, auth-worker/did.rs). Neither ADR exists in docs/ —
- **Decision:** FINISH — author ADR-124 (gitmark/blocktrails trail + I1-I4 invariants) and ADR-125 (Multikey DID doc) into docs/adr/ and add them to the register, or FREEZE with an explicit register stub if they are meant to be upstream-numbered like 001-0


## P2

### (auth-worker) Static-configured admins (ADMIN_PUBKEYS) can authenticate but cannot perform moderation actions  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-auth-worker/src/moderation.rs:121-154 (admin_set queries only members+whitelist, no ADMIN_PUBKEYS) and :217-220 (validate_moderation_event uses that narrower set) vs crates/nostr-bbs-auth-worker/src/admin.rs:65-73 (is_admin/require_admin honour static ADMIN_PUBKEYS)
- **Detail:** handle_action gates on require_admin (which resolves admin via is_admin = static ADMIN_PUBKEYS ∪ RELAY_DB whitelist ∪ DB members, admin.rs:57-104), then independently validates the embedded signed moderation event against admin_set(env). admin_set reads ONLY the two D1 tables (MEMBERS_ADMIN_LIST_SQL + WHITELIST_ADMIN_LIST_SQL) and omits the static ADMIN_PUBKEYS env set. So a deploy whose only admi
- **Decision:** FIX — seed admin_set from nostr_bbs_core::admin_pubkeys_from_env_str(ADMIN_PUBKEYS) as well, or validate the embedded event's signer via is_admin(), so the two admin authorities agree.

### (auth-worker) Native pod provisioning relies on solid-pod-rs provision (alpha.3) which leaves the owner root ACL unset, locking the owner out  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-auth-worker/src/lib.rs:600-728 (handle_native_pod_provision → :703-724 forwards to /_admin/provision/{pubkey} and returns upstream status verbatim); depends on solid_pod_rs::provision::provision_pod owner-ACL behaviour (P1-d)
- **Detail:** handle_native_pod_provision (admin NIP-98 gated) forwards to the native solid-pod-rs server at POST {NATIVE_POD_URL}/_admin/provision/{pubkey} and treats a 2xx as a successfully provisioned, usable pod. In the pinned solid-pod-rs 0.5.0-alpha.3 (no closeout fix), provision_pod leaves the owner root .acl unset, so deny-by-default locks the pod owner out of their own pod. The forum pins alpha.3, so e
- **Decision:** FREEZE — track/require the solid-pod-rs closeout fix (owner root ACL seeded) before relying on this endpoint; until then document that provisioned pods need a manual owner-ACL write, or have the native server apply the P1-d fix.

### (clients-mesh) MediaEmbed YouTube detection indexes original URL with an offset found in the lowercased copy → panic on crafted post  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/components/media_embed.rs:41-44 (`let lower = url.to_lowercase(); ... lower.find("v=") ... &url[pos + 2..]`); reached via message_bubble.rs:79-80,219
- **Detail:** detect_media computes `pos = lower.find("v=")` on url.to_lowercase() and then slices the ORIGINAL string `&url[pos + 2..]`. to_lowercase() can change byte length for non-ASCII (e.g. 'İ' U+0130 lowercases to two code points), so pos is an offset into a string of different length than url; `&url[pos + 2..]` can land off a char boundary and panic. detect_media is invoked during render for any content
- **Decision:** FIX — run find and slice on the same string (search original case-insensitively or slice `lower`), or parse the query with a URL parser. Kills the panic vector.

### (clients-mesh) LinkPreview renders worker-supplied url as an <a href> with no scheme validation (client over-trusts preview worker)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/components/link_preview.rs:170 (`let href = data.url.clone()...`), :178 (`href=href`); image src also unvalidated at :185
- **Detail:** On PreviewState::Loaded the card sets `href=href` where href = data.url returned by the link-preview worker's JSON, which is ultimately derived from the target page's attacker-controllable og:url/canonical (or worker echo). title/description are strip_tags'd and text-escaped by Leptos, and image is only an <img src>, but the href receives no javascript:/data: scheme filtering. If a preview worker
- **Decision:** FIX — validate href starts with http(s):// (fall back to the original url_for_display otherwise) and apply the same guard to image src. Cheap defence-in-depth against a single worker bug becoming client XSS.

### (config-setup-canary) URL scheme validation uses naive starts_with prefix matching — localhost bypass, no host parse  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/src/validate.rs:8-9, 29-31, 39, 47-48, 107, 150-151, 167-169; unused dep crates/nostr-bbs-config/Cargo.toml:21
- **Detail:** Every transport-security check is a string prefix test, not a parse. `starts_with("http://localhost")` matches http://localhost.attacker.com; `starts_with("https://")` accepts https://<anything> with no host validation; `starts_with("wss://")` / `ws://localhost` likewise. So a config that looks HTTPS-only can point pod/relay/mesh/nip05/git/governance URLs at attacker-controlled or plaintext-adjace
- **Decision:** FIX — parse with url::Url and assert scheme + host=="localhost" (or explicit dev allowlist); it is a public forum and these URLs feed server-side fetches.

### (config-setup-canary) [native_pod] section is completely unvalidated yet backs a server-side admin-key POST  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/src/validate.rs (no native_pod check, contrast git/governance URL checks at 149-175); schema.rs:330-362; consumption crates/nostr-bbs-auth-worker/src/lib.rs:682-712 (env-sourced, X-Pod-Admin-Key over unvalidated scheme)
- **Detail:** validate_config has no branch for native_pod at all: base_url and admin_provision_url accept any string, including http:// / plaintext, and enabled=true with an empty base_url passes. admin_provision_url is the pod-provisioning control-plane. The auth-worker forwards a secret `X-Pod-Admin-Key` header to the native pod URL with no https enforcement, so a plaintext/typo'd endpoint leaks the admin ke
- **Decision:** FIX — validate native_pod.base_url/admin_provision_url as https-only when enabled, and reconcile config-vs-env so the documented fields are actually consumed.

### (config-setup-canary) Large parts of the schema are aspirational/unwired (provision, export, git, governance routing)  — *✓ confirmed*
- **Evidence:** grep counts across crates/ excluding config crate: keys_at_signup/privkey_filename/private_dir/payments.enabled/export.enabled/git.enabled/governance.route/clone_url_base = 0 each; schema.rs:368-475 (provision/export/git blocks)
- **Detail:** The schema advertises a rich operator surface, but many fields have zero consumers anywhere outside the config crate: keys_at_signup, privkey_filename, private_dir, payments.enabled, export.enabled, git.enabled, governance.route, clone_url_base all resolve to 0 external references. Operators tuning these (e.g. enabling export, git, or a governance route via forum.toml) get no effect and no error,
- **Decision:** FINISH the wiring or DELETE/trim the unimplemented sections and mark remaining ones explicitly as planned so operators aren't misled.

### (config-setup-canary) nostr-bbs-setup-skill is 100% stubs — operator-onboarding/secret provisioning unimplemented, still published as 1.0.0-beta.3  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-setup-skill/src/lib.rs:97-228 (all NotYetImplemented/Unsupported); Cargo.toml:1-13 (no publish=false, description overstates capability); README 'todo!()' claim vs code
- **Detail:** Every Provider::provision / render_wrangler returns NotYetImplemented (Turnkey returns Unsupported). ADR-079's promise to 'walk an operator from git clone to running forum … provision D1/KV/R2/Routes/Domains and write the wrangler.toml overlay' is not built, so the safety-critical automated secret provisioning that this dimension is meant to audit does not exist — operators must hand-wire CF Worke
- **Decision:** FINISH or set publish=false + correct the README/description until the providers exist; a stub secret-provisioning kit on crates.io is a trust hazard.

### (core-protocol) did.rs DID/WebID helpers inherit un-published solid-pod-rs alpha.3 defects (false identity binding, no alsoKnownAs backlink)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/src/did.rs:63-65 (verify_webid_tag delegate) and 86-145 (render_did_document_tier1/tier3 delegate); pin at Cargo.toml:141 (solid-pod-rs = 0.5.0-alpha.3); consumed at crates/nostr-bbs-pod-worker/src/lib.rs:742
- **Detail:** did.rs is a thin verbatim delegator to solid_pod_rs::did_nostr_types for render_did_document_tier1/tier3 and verify_webid_tag. The forum pins solid-pod-rs 0.5.0-alpha.3, which per the just-completed upstream audit still asserts a false did:nostr->identity binding for any pubkey and whose resolve_nostr_to_webid trusts alsoKnownAs with no backlink verification (fixed only on the unpublished closeout
- **Decision:** FREEZE then FIX — bump the solid-pod-rs pin to the fixed release once the closeout branch publishes; until then treat verify_webid_tag as syntactic-only and require an out-of-band backlink check at the pod-worker gate.

### (pod-worker) Native pod-git anchoring subsystem (ADR-124 §5.4) is fully implemented but wired to nothing  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/lib.rs:16 (#![allow(dead_code)]), lib.rs:35-36 (mod pod_git_anchor, gated, never used), provision.rs:116-404 (provision_pod has no branch to pod_git_anchor; only cfg reference is the doc comment at line 111), pod_git_anchor.rs:365-422 (bootstrap fn), pod_git_anchor.rs:586 (only caller is the test)
- **Detail:** pod_git_anchor.rs implements the complete native tier — bootstrap_pod_identity_and_trail (git init → write agent.did.json → git config nostr.privkey → genesis commit → gitmark.json/blocktrails.json → commit), plus ensure_repo/pull/commit/push/is_git_clean. Nothing invokes it: provision_pod (the only provisioning entrypoint, shared by both `/.pods` and `/pods/{pk}/.provision`) has NO cfg branch tha
- **Decision:** FINISH or FREEZE — either wire bootstrap_pod_identity_and_trail into provision_pod behind #[cfg(not(target_arch="wasm32"))] (and fix the secret/anchor defects first), or explicitly mark the module `#[cfg(feature="native-git-pods")]`/experim

### (pod-worker) Agent BIP-340 secret key leaked via git argv and embedded verbatim in error messages  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/pod_git_anchor.rs:122-133 (set_git_privkey passes privkey_hex as argv), pod_git_anchor.rs:433-448 (run_git embeds `args.join(" ")` — including the privkey — into the error at lines 439 and 443)
- **Detail:** set_git_privkey stores the agent's raw secret key by running `git config --local nostr.privkey <hex>` with the secret as a command-line argument. On the documented multi-user agentbox host, process argv is world-readable via /proc/<pid>/cmdline for the provisioning window, exposing the key to any local user. Worse, run_git formats the FULL argument vector — including the secret — into AnchorError:
- **Decision:** FIX — write nostr.privkey directly into .git/config on the filesystem (mode 600) instead of via argv, and redact the privkey (and the whole nostr.privkey value) from run_git error strings before they can be logged.

### (preview-search-ascii) Image decompression-bomb DoS: MAX_PIXELS enforced only AFTER full decode; MAX_PIXELS itself exceeds isolate memory  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-ascii/src/lib.rs:249 (load_from_memory), :251 (post-decode pixel check), :261 (MAX_PIXELS=24_000_000); fetch cap crates/nostr-bbs-preview-worker/src/ssrf.rs:41 (MAX_IMAGE_BYTES=10MB); call site crates/nostr-bbs-preview-worker/src/lib.rs:457; image crate version workspace Cargo.toml:154 (image 0.24)
- **Detail:** render_bytes calls image::load_from_memory(bytes) which fully decodes the image into memory, and only THEN checks w*h > MAX_PIXELS. A ~1-10MB highly-compressible PNG/GIF/WebP (MAX_IMAGE_BYTES caps the encoded fetch at 10MB) decodes to hundreds of MB to several GB, OOM-aborting the 128MB Cloudflare Workers isolate before the guard runs — a per-request DoS reachable by /ascii?url=http://attacker/bom
- **Decision:** FIX — decode via image::io::Reader with Limits (bound max_alloc and max dimensions) so oversize inputs are rejected pre-allocation, and lower MAX_PIXELS to something the 128MB isolate can actually hold (e.g. 4-8MP).

### (preview-search-ascii) /ascii cache key built from UNCLAMPED attacker cols → cache-buster amplifying fetch+decode load  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-preview-worker/src/lib.rs:411-413 (opts.cols = raw c), :417 (ascii_cache_key(..., opts.cols, ...)); clamp that the key misses at crates/nostr-bbs-ascii/src/lib.rs:102-108 (sanitized) and :35 (MAX_COLS=400)
- **Detail:** handle_ascii sets opts.cols directly from the raw query u32 and then builds the CF Cache key with that raw value. Column clamping (to MAX_COLS=400) happens only later, inside render_luma/sanitized — the cache key never sees the clamped value. Every cols in 401..=u32::MAX therefore produces a DISTINCT cache key but an IDENTICAL render, so an attacker iterating cols guarantees a cache MISS on every
- **Decision:** FIX — clamp cols to the ascii crate's MAX_COLS range before both the RenderOptions and the cache key (expose the clamp, e.g. RenderOptions::default().sanitized(), and key on the sanitized value).

### (preview-search-ascii) SSRF denylist bypasses (octal / short-form / mixed-radix IPv4) ship live because no allowlist is configured by default  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-preview-worker/src/ssrf.rs:404-414 (parse_ipv4 four-decimal-only), :308-315 (only pure integer/hex hostnames blocked), :330-333 (parse_ipv4 gate); no allowlist in crates/nostr-bbs-preview-worker/wrangler.toml:12-13
- **Detail:** parse_ipv4 only accepts exactly four decimal octets, so several IPv4 encodings that inet_aton-style resolvers collapse to loopback/link-local are NOT blocked by the denylist: http://0177.0.0.1/ (dotted-octal 127.0.0.1), http://127.1/ (short form), http://0x7f.0.0.1/ (mixed hex). The code only special-cases pure-integer and pure-0x-hex whole hostnames (ssrf.rs:308-315), missing these dotted forms.
- **Decision:** FIX — normalise IPv4 with inet_aton semantics (octal/hex/short-form) before the private-range check, AND set PREVIEW_ALLOWED_HOSTS in the default wrangler.toml so the authoritative allowlist is on by default.

### (preview-search-ascii) Unauthenticated billable Workers-AI on /embed and /search?query → cost-amplification abuse  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-search-worker/src/lib.rs:331-365 (handle_embed, :356 batch cap 100, no length cap), :268 & :365 (embed_texts → AI), :255-277 (handle_search embeds query); embed at crates/nostr-bbs-search-worker/src/embed.rs:68-85; rate limiter (non-atomic, fail-open) crates/nostr-bbs-rate-limit/src/lib.rs:39-60 invoked at crates/nostr-bbs-search-worker/src/lib.rs:505
- **Detail:** /embed and /search (when given `query` text) call embed::embed_texts which runs the billable Cloudflare Workers AI BGE model, with no authentication. /embed accepts up to 100 texts per request and there is no per-text length cap, so a single request triggers up to 100 inferences; the only control is the shared IP rate limiter (100 req/60s), which is itself a non-atomic, fail-open KV get+put (burst
- **Decision:** FIX — cap per-text length and lower the batch limit, tighten the rate budget on AI-backed routes, and consider requiring auth (or a signed capability) for /embed.

### (preview-search-ascii) Preview JSON emits entity-DECODED, un-escaped attacker HTML in title/description/site_name (unsafe-by-default contract)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-preview-worker/src/parse.rs:87-137 (decode_html_entities un-escapes), :158-162 (extract_meta returns decoded value), :176-188 (title/description/site_name); consumer mitigation that masks it: crates/nostr-bbs-forum-client/src/components/link_preview.rs:172-173 (strip_tags) & :199-208 (Leptos text interp)
- **Detail:** extract_meta captures og:* content from attacker-controlled remote HTML and then actively entity-DECODES it (decode_html_entities turns &lt; into <, &#60; into <, etc.) before returning it un-escaped in the preview JSON. So an attacker page with content="&lt;img src=x onerror=alert(1)&gt;" yields title="<img src=x onerror=alert(1)>" in the response. XSS-safety then depends entirely on every downst
- **Decision:** FIX (defense in depth) — do not entity-decode into the output; HTML-escape / tag-strip preview text fields server-side and length-cap them, so the JSON is safe regardless of consumer behaviour.

### (preview-search-ascii) Twitter oEmbed path yields output no client renders (dead functional path) and a latent raw-HTML sink  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-preview-worker/src/oembed.rs:62-103 (returns html/author_name, no OG fields) and crates/nostr-bbs-preview-worker/src/lib.rs:305-314 (TwitterEmbedResponse); consumer shape missing these fields: crates/nostr-bbs-forum-client/src/components/link_preview.rs:42-54 (OgData has no html/author_name)
- **Detail:** For twitter.com/x.com URLs the worker branches to fetch_twitter_embed and returns {type:'twitter', html, author_name, author_url, provider_name} with NO title/description/image/site_name. The only consumer, the forum-client LinkPreview, deserialises solely OG fields (title/description/image/site_name/url) and has no `html`/`author_name` field, so a twitter/x link renders an empty/blank preview car
- **Decision:** FIX or DELETE — either map the twitter oEmbed into the OG fields the client actually reads (title/author→site_name, etc.) so twitter links preview, or drop the twitter special-case entirely; do not expose a raw `html` field.

### (preview-search-ascii) Search silently returns meaningless results when Workers AI is unavailable (hash-fallback space mismatch, not surfaced on /search)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-search-worker/src/embed.rs:68-81 (per-call silent fallback), :109-130 (non-semantic hash embedder); handle_search does not report model: crates/nostr-bbs-search-worker/src/lib.rs:255-277 & :303-329 (no semantic flag in the search response)
- **Detail:** embed_texts falls back per-call to a deterministic hash embedder whenever the AI binding is absent or the inference errors. Stored vectors are BGE-semantic (or client-supplied at ingest); the hash fallback lives in a completely different, non-semantic space. If a /search `query` is embedded via the fallback during a transient AI outage, cosine ranking against the BGE-space store is meaningless — y
- **Decision:** FIX — surface the model/semantic flag on the /search response, and prefer failing closed (503) for query-embedding when AI is unavailable rather than returning nonsense-ranked results.

### (relay-ratelimit) Entire relay funnels through a single global Durable Object (one V8 isolate) — architectural DoS bottleneck  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/lib.rs:169 (get_by_name("main")); broadcast fan-out broadcast.rs:66-129
- **Detail:** Every WebSocket upgrade routes to env.durable_object("RELAY").get_by_name("main") — one single-threaded DO instance for the whole relay. There is no sharding by zone/room/pubkey. All connections, all subscription matching (broadcast_event iterates every session × every subscription × every filter for every event), and all per-event gate D1 lookups serialize on one CPU. A moderate flood — even stay
- **Decision:** FIX/ACCEPT — shard the DO (e.g. by channel/zone id) so load distributes across isolates; if a single instance is an intentional constraint, document the ceiling and add global admission control. At minimum bound the broadcast fan-out cost.

### (relay-ratelimit) Rate limits are per-IP only and bypassable by IP rotation; missing header collapses to a shared bucket; no per-pubkey write quota  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/mod.rs:50 (MAX_CONNECTIONS_PER_IP), mod.rs:96-107 (per-IP conn check), mod.rs:99 ("unknown" fallback); broadcast.rs:137-154 (per-IP events/sec, no per-pubkey limit)
- **Detail:** MAX_CONNECTIONS_PER_IP=20 and MAX_EVENTS_PER_SECOND=10 are keyed solely on CF-Connecting-IP. An attacker with an IPv6 /64 (2^64 addresses), Tor, or a botnet rotates IPs and multiplies both limits without bound. When the header is absent, ip collapses to the literal "unknown", so all header-less clients share one connection/event bucket (either a shared DoS bucket or trivially exhausted). There is
- **Decision:** FIX — add a per-pubkey (authenticated identity) write quota in addition to per-IP, treat missing CF-Connecting-IP as deny/challenge rather than a shared bucket, and consider per-/64 bucketing for IPv6.

### (relay-ratelimit) Connection-limit cap resets to zero across DO hibernation (bypass)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/session.rs:67-174 (recover_session rebuilds sessions + next_session_id only; connection_counts untouched); mod.rs:102-108 (cap check reads connection_counts); session.rs:251-259 (remove_session decrement)
- **Detail:** recover_session rebuilds the in-memory `sessions` map from WebSocket tags after hibernation but never rebuilds `connection_counts`. Live WebSockets survive hibernation, but the per-IP counter is cleared, so after each hibernation cycle an attacker gets a fresh 20-connection budget per IP on top of already-open sockets. remove_session then under-decrements (reads count via unwrap_or(1) against an e
- **Decision:** FIX — rebuild connection_counts from the `ip:` tags of state.get_websockets() during recovery (or derive the live count from get_websockets() at check time instead of a mutable counter).

### (relay-ratelimit) Shared KV rate limiter is non-atomic (TOCTOU race), eventually-consistent per-PoP, fail-open, and a fixed window mislabeled as sliding  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-rate-limit/src/lib.rs:32-63 (get-then-put, fail-open line 41, fixed bucket line 44); consumers auth-worker/src/lib.rs:161, preview-worker/src/lib.rs:519, search-worker/src/lib.rs:505
- **Detail:** check_rate_limit does a KV get, then a separate KV put(current+1) with no atomicity. Concurrent requests all read the same `current`, all see < limit, and all pass — the limit is only soft and is exceeded by the concurrency factor under a burst. Cloudflare KV reads are served from a per-PoP cache that lags writes by up to ~60s, so the counter under-counts globally (an attacker spread across PoPs s
- **Decision:** FIX — move the counter to a Durable Object or D1 atomic INSERT/UPDATE (like the replay store) for true atomicity, or use Cloudflare's native Rate Limiting binding; at minimum fix the doc/window mismatch and reconsider fail-open for security

### (relay-ratelimit) Report auto-hide can be triggered by a single reporter (report-bomb / censorship)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-relay-worker/src/moderation.rs:91-100 (COUNT(*) over rows, no distinct/trust filter), moderation.rs:74-89 (insert omits reporter_trust_level); write-side TL1 gate nip_handlers.rs:300-308
- **Detail:** Auto-hide fires when 3+ pending reports exist for an event, but the threshold query counts report ROWS, not DISTINCT reporters, and applies no reporter trust filter in the count. A single TL1+ member can publish 3 distinct kind-1984 report events (3 unique report_event_ids) targeting the same victim event and auto-hide it — griefing/censorship of any content by one account. The `reports` table onl
- **Decision:** FIX — count DISTINCT reporter_pubkey (and optionally weight by reporter trust) and add a UNIQUE(reported_event_id, reporter_pubkey) constraint so one account cannot satisfy the threshold alone.

### (relay-ratelimit) Event size is effectively unbounded (no cap on values-per-tag or total serialized size)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:512-545 (validate_event: MAX_TAG_COUNT/MAX_TAG_VALUE_SIZE checked per value, no values-per-tag or total-size cap)
- **Detail:** validate_event caps content (64KB), tag COUNT (2000), and per-VALUE length (1024) but not the number of values within a tag, nor the total serialized event size. A tag is a Vec<String>; an event with 2000 tags each holding thousands of 1KB values is accepted, bounded only by Cloudflare's ~1 MiB WebSocket frame. Each such ~1 MiB event is signature-verified, JSON-serialized, stored in D1 with no ded
- **Decision:** FIX — add a total-serialized-size cap and a per-tag value-count cap in validate_event, and reject frames above an explicit byte ceiling before parsing.

### (relay-ratelimit) Per-event zone/cohort gate does un-memoized D1 lookups per event on COUNT/REQ/broadcast  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:942-999 (authorize_event per-event get_channel_zone/has_zone_access), resolve_viewer_context nip_handlers.rs:905-929; broadcast.rs:104-116
- **Detail:** authorize_event resolves the channel zone (get_channel_zone) and membership (has_zone_access) per event, and the broadcast path calls resolve_viewer_context (effective_pubkey + get_viewer_cohorts, D1) per candidate session per event. Nothing memoizes get_channel_zone across the many events of one channel within a single REQ/COUNT/broadcast, so a REQ/COUNT returning N kind-42 events issues O(N) zon
- **Decision:** FIX — add a short-TTL cache for channel→zone and pubkey→cohorts (mirroring mod_cache/admin_cache), and resolve each distinct channel_id once per REQ/COUNT/broadcast.

### (stubs-adrs) Dead under-provisioning path: auth-worker pod::provision_pod has no caller and would silently under-provision  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-auth-worker/src/pod.rs:29-116 (no caller); crates/nostr-bbs-auth-worker/src/lib.rs:318,557; docs/diagrams/00-anomaly-register.md:O3
- **Detail:** auth-worker/src/pod.rs:29 provision_pod is dead — the only use of the pod module is handle_profile (lib.rs:318); provision now flows through handle_native_pod_provision (lib.rs:557) which proxies to the native solid-pod-rs server. This is the anomaly register O3 residual ('dead under-provisioning path flagged for deletion'). If ever re-wired it writes only a single KV acl:{pubkey} document plus a
- **Decision:** DELETE — remove the dead provision_pod fn (keep handle_profile); provisioning is owned by handle_native_pod_provision and pod-worker/provision.rs.

### (stubs-adrs) Acknowledged NIP-29 TODO admits admin-signed group metadata that clients trust as relay-authoritative  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:324-338; docs/diagrams/00-anomaly-register.md:O2
- **Detail:** nip_handlers.rs:327-330 carries an explicit 'NIP-29 TODO' at the group-management gate: kinds 39000-39002 (group metadata) are admitted from any admin client after an h-tag/admin check, but the spec requires this metadata to be relay-key-generated, not accepted from arbitrary clients. This is anomaly register O2 (HIGH). A compromised or rogue admin key can inject arbitrary group metadata (name, me
- **Decision:** FINISH — have the relay generate/sign 39000-39002 with the relay key on admin request and reject client-supplied group-metadata events; or FREEZE the feature behind a config flag until then.

### (stubs-adrs) solid_pod_rs::export re-export shim and solid-pod-rs-phase1 feature are dead on the shipped wasm32 target (build landmine)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-pod-worker/src/export.rs:10-19; crates/nostr-bbs-pod-worker/Cargo.toml:21-24; /home/devuser/workspace/solid-pod-rs/crates/solid-pod-rs/Cargo.toml:237,243,250; docs/consumer-surface-map.md:47
- **Detail:** export.rs:17-19 re-exports solid_pod_rs::export::* but is gated #[cfg(feature="solid-pod-rs-phase1")]. That feature (pod-worker Cargo.toml:21-24) enables solid-pod-rs/{provision-keys,nip05-endpoint,export-jsonld}, all of which pull tokio-runtime upstream (verified in solid-pod-rs Cargo.toml:237,243,250 — export-jsonld=["tokio-runtime"]). tokio-runtime cannot compile on wasm32-unknown-unknown, so e
- **Decision:** FREEZE + document — either delete export.rs (no route consumes it) or add a compile_error!-guarded note that solid-pod-rs-phase1 is native-only; update consumer-surface-map so ::export is not listed as a live wasm32 consumption.

### (stubs-adrs) Blanket #![allow(dead_code)] on 7 crates masks genuinely dead code from the compiler  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-pod-worker/src/lib.rs:16; crates/nostr-bbs-relay-worker/src/lib.rs:20; crates/nostr-bbs-search-worker/src/lib.rs:19; crates/nostr-bbs-auth-worker/src/lib.rs:14; crates/nostr-bbs-preview-worker/src/lib.rs:20; crates/nostr-bbs-upstream-canary/src/lib.rs:28; crates/nostr-bbs-forum-client/src/main.rs:4
- **Detail:** Six worker crates plus the forum-client set crate-wide #![allow(dead_code)] (pod-worker/src/lib.rs:16, relay-worker/src/lib.rs:20, search-worker/src/lib.rs:19, auth-worker/src/lib.rs:14, preview-worker/src/lib.rs:20, upstream-canary/src/lib.rs:28, forum-client/src/main.rs:4). This silences the exact warning that would have caught the dead auth-worker provision_pod, and it makes any future dead cod
- **Decision:** FIX — remove the crate-level allows, let the build surface dead code, and apply narrow #[allow(dead_code)] only to the specific items that are intentionally retained (with a reason comment).

### (stubs-adrs) Reference-vector conformance suite stubs all crypto/wire validation and still tests a removed NIP-26 feature  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/tests/upstream_vectors/all_fixtures.rs:6-8,26-40,59-60; docs/diagrams/00-anomaly-register.md:R4
- **Detail:** all_fixtures.rs:6-8 states the substrate-side crypto/wire validation hooks are 'stubbed pending PRD-009 F26 absorption'. Each fixture_test only asserts the metadata block and a minimum vector count (all_fixtures.rs:26-40) — it never validates a single NIP-01/04/19/44 vector against the implementation, giving false conformance confidence. It also declares nip26_delegation_load_and_validate (all_fix
- **Decision:** FINISH the crypto assertions (or FREEZE the suite honestly as a fixture-shape smoke test), and DELETE the nip26 fixture test for the removed feature.


## P3

### (auth-worker) Moderation action does not require the embedded signed event's author to equal the NIP-98 signer  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-auth-worker/src/moderation.rs:194-220 (no body.event.pubkey == admin_pubkey check) contrasted with the enforced check at :313-320
- **Detail:** handle_action derives admin_pubkey from require_admin (the NIP-98 signer) and stores it as performed_by, but the body.event (the signed kind-3091x moderation event) may be signed by a DIFFERENT admin — it is only checked to be signed by SOME member of admin_set, never that body.event.pubkey == admin_pubkey. handle_report does enforce this equality (moderation.rs:313-320: 'Reporter pubkey in event
- **Decision:** FIX — add `if body.event.pubkey != admin_pubkey { 403 }` in handle_action, mirroring handle_report, so the signed action is bound to the authenticating admin.

### (auth-worker) Dead code: pod::provision_pod is never called (parallel pod/ACL implementation that can rot)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-auth-worker/src/pod.rs:29-116 (definition); grep for 'provision_pod' shows no caller in crates/nostr-bbs-auth-worker/src; handle_profile (pod.rs:119) is the only used export
- **Detail:** pod::provision_pod is a full KV/R2 pod-provisioning implementation (writes an owner Read/Write/Control ACL to KV and a profile card to R2) but has no callers anywhere in the worker (grep finds only the definition). Provisioning is actually delegated to the native server via handle_native_pod_provision. The dead function duplicates ACL/pod semantics that live authoritatively in the pod-worker and c
- **Decision:** DELETE — remove pod::provision_pod (and PodInfo if unused) or wire it to a real route; keep pod provisioning single-sourced to avoid ACL drift.

### (auth-worker) Rate limiter is fail-open, non-atomic (TOCTOU), and collapses to a shared bucket when CF-Connecting-IP is absent  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-rate-limit/src/lib.rs:39-42 (fail-open on KV error), :47-62 (get-then-put race), :66-72 (client_ip → 'unknown' fallback); applied once at crates/nostr-bbs-auth-worker/src/lib.rs:159-167
- **Detail:** The single global gate (20 req / 60s per IP) protects all auth + /api endpoints of a public forum but: (a) check_rate_limit returns true on any KV error (fail-open), so a KV blip disables throttling; (b) it does a non-atomic get-then-put, so N concurrent requests all read the same count and each increment, letting a burst exceed the limit; (c) client_ip falls back to the literal 'unknown' when CF-
- **Decision:** IMPROVE — back the counter with a Durable Object or atomic KV op and decide fail-closed vs fail-open deliberately; treat missing CF-Connecting-IP as its own conservative bucket.

### (auth-worker) NIP-98 u-tag is not bound to the query string on GET endpoints  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-auth-worker/src/admin.rs:178-180 (canonical_url = origin+path, no query); consumed by GET handlers e.g. crates/nostr-bbs-auth-worker/src/governance_api.rs:386-400 and moderation handle_list_actions (moderation.rs:370-390)
- **Detail:** admin::canonical_url builds the NIP-98 comparison URL as origin+path only, dropping the query string. GET endpoints that accept query filters (e.g. /api/mod/actions?target=&action=, /api/governance/cases?state=) therefore accept a token whose signed u-tag covers only the path, so the token is not bound to the specific filter parameters. Impact is low — these are admin-gated read filters, not autho
- **Decision:** ACCEPT (or optionally include the canonicalised query in the signed u-tag) — low risk given these are admin-only read filters.

### (clients-mesh) Federation mesh crate is an unshipped scaffold / dead code — no cross-instance AUTH trust boundary is actually enforced  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-mesh/src/lib.rs:12-23 (status: scaffold, not a relay-worker dependency, standalone short-circuits), :108-110 (mesh_anchor_tags self-asserted d tag)
- **Detail:** nostr-bbs-mesh ships only abstract traits/state (MeshTransport, PeerSession, mesh_anchor_tags) and self-documents as 'Scaffold only — federation is designed, not shipped.' No concrete MeshTransport implementation exists anywhere, and the crate is not a dependency of nostr-bbs-relay-worker, so setting `[mesh] mode = "federated"` in operator config is silently inert (standalone code path with no fed
- **Decision:** FREEZE + FIX-config — keep the scaffold but make relay-worker reject/loudly warn on `mode="federated"` until a MeshTransport ships, so operators cannot believe an inert AUTH boundary is protecting them.

### (clients-mesh) AsciiImg injects worker-returned HTML via inner_html trusting only the Content-Type header  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-bbs-client/src/ascii_img.rs:99-101 (inner_html=html), :247-283 (fetch_ascii accepts any text/html body); source URL from user content via extract_image_urls
- **Detail:** AsciiImg fetches an HTML fragment from the preview-worker /ascii endpoint (or a pod-worker with ?format=ascii) and injects it verbatim with inner_html, gated only by resp.ok() and a content-type contains('text/html') check. The source image URL is extracted from untrusted post content, so the preview-worker performs a server-side fetch of an arbitrary attacker URL (worker-side SSRF concern) and th
- **Decision:** ACCEPT-with-note or FIX — architecturally the fragment must be first-party; at minimum treat the worker as a trust boundary and constrain injected markup (allowlist <pre>/<span class=pN>) or escape defensively so a worker regression cannot

### (clients-mesh) Client trusts core gift-wrap unwrap that skips seal signature and rumor↔seal pubkey-binding checks  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/dm/mod.rs:635 (uses unwrapped.sender_pubkey without independent check); crates/nostr-bbs-core/src/gift_wrap.rs unwrap_gift (~line 300-360: kind-only validation, returns sender_pubkey: seal.pubkey.clone(), no verify_event_strict(&seal), no rumor.pubkey==seal.pubkey assert)
- **Detail:** The DM store derives sender identity from unwrapped.sender_pubkey (= seal.pubkey) and uses it for is_sent and display, trusting core's unwrap_gift, which validates only layer KINDS — it never verifies the seal's Schnorr signature and never asserts rumor.pubkey == seal.pubkey (a NIP-59 requirement). Sender impersonation is not practically exploitable because NIP-44 ECDH binds the seal ciphertext to
- **Decision:** FIX (core) — have unwrap verify the seal signature and require rumor.pubkey == seal.pubkey; client keeps trusting unwrapped.sender_pubkey once that holds.

### (clients-mesh) Client provision flow assumes the worker grants the owner write access; alpha.3 provision leaves owner root ACL unset  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-forum-client/src/pages/signup.rs:174-199 and settings.rs:1473 (provision_pod treats 201/409 as success, failure non-fatal, no owner-ACL/403 handling); pod-worker side consumes solid_pod_rs::provision::provision_pod (alpha.3, missing owner root ACL per audit P1-d)
- **Detail:** signup/settings provision_pod POSTs to the pod-worker's /.provision and treats 201/409 as success and any failure as non-fatal ('lazy path still provisions'). It has no handling for the case the just-fixed-but-unpublished solid-pod-rs audit calls out (P1-d): pinned solid-pod-rs 0.5.0-alpha.3 provision_pod leaves the owner's root ACL unset under deny-by-default, locking the owner out of their own p
- **Decision:** ACCEPT client-side + bump dependency — the real fix is upgrading past solid-pod-rs alpha.3 in the pod-worker; the client should surface a distinct 'pod exists but access denied' error so the owner-lockout is diagnosable rather than a silent

### (config-setup-canary) Dangerous default: provision.keys_at_signup = true (store member private key server-side)  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-config/src/schema.rs:388-389 (default=bool_true), 398-407; consumption boundary: grep keys_at_signup|privkey_filename|private_dir outside config = 0 consumers; solid-pod-rs P1-d (provision_pod owner root ACL unset) inherited via pinned alpha.3
- **Detail:** The schema default (bool_true) and Provision::default() both set keys_at_signup=true, meaning the generated NIP-19 private key is written into the pod (privkey.jsonld under /private/) at signup unless the operator explicitly opts out — the insecure posture is the default. The safer on-device / never-store-private-keys mode requires deliberate keys_at_signup=false. This private key file relies enti
- **Decision:** FIX — flip the default to false (secure default) and finish the wiring only after upgrading past solid-pod-rs alpha.3 owner-ACL fix.

### (config-setup-canary) webauthn.expected_origin is never validated (no https / no rp_id consistency check)  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-config/src/schema.rs:84-86 (expected_origin field); validate.rs:17-26 (only rp_id validated); no expected_origin branch anywhere in validate.rs
- **Detail:** validate_config checks webauthn.rp_id (non-empty, no scheme) but never touches expected_origin, which is the security-critical value passkey assertions are matched against. A downgraded (http://), malformed, or mismatched expected_origin silently passes; there is also no check that rp_id is a registrable-domain suffix of expected_origin / deployment.hostname, which WebAuthn requires. Misconfigurat
- **Decision:** FIX — require expected_origin to be https:// (or http://localhost dev) and to have rp_id as a registrable suffix.

### (config-setup-canary) Public-key config fields validated inconsistently (welcome_bot_pubkey, token.issuer unchecked)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/src/schema.rs:216-218 (welcome_bot_pubkey), 577-579 (issuer); validate.rs:75-79 & 177-183 validate the other two but no branch for these; consumer crates/nostr-bbs-auth-worker/src/welcome.rs:361-364
- **Detail:** admin.static_pubkeys and governance.agent_pubkeys get a strict 64-char-hex check, but invites.welcome_bot_pubkey and payments.token.issuer — also runtime pubkeys — are never validated. welcome_bot_pubkey is used by the auth-worker to sign/attribute welcome DMs; a malformed value fails silently at runtime instead of at config load.
- **Decision:** FIX — apply the same 64-hex check to welcome_bot_pubkey and token.issuer when present.

### (config-setup-canary) pod.storage_backend not validated against documented enum; cf-r2 allowed with no bucket  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/src/schema.rs:88-98; validate.rs has no storage_backend/r2_bucket branch
- **Detail:** storage_backend is documented as one of {"fs","s3","cf-r2"} and r2_bucket 'only applies to cf-r2', but validate_config never checks storage_backend membership and never requires r2_bucket when storage_backend=="cf-r2". A typo ("r2", "S3") or a cf-r2 backend with no bucket is silently accepted, surfacing only as a runtime storage failure.
- **Decision:** FIX — small enum + conditional-required check.

### (config-setup-canary) upstream-canary hardcodes one NIP-44 vector and references a non-existent fixture path  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-upstream-canary/src/lib.rs:56-67 (hardcoded vector + TODO), :25 (dangling docs/specs/fixtures path), :10 (1.84 vs workspace 1.85); real file tests/fixtures/nip44-v2.json
- **Detail:** smoke_nip44_conv_key inlines a single hand-copied (sk,pk,expected) triple instead of loading the vendored suite, with an in-code note deferring 'Phase 3 follow-up: switch to loading from fixture file via include_str! + serde_json'. The module doc cites the fixture at docs/specs/fixtures/nip44-v2.json, which does not exist (the synced file is tests/fixtures/nip44-v2.json). So the canary validates o
- **Decision:** FINISH — load vectors from tests/fixtures/nip44-v2.json via include_str! so the canary tracks the vendored suite; or ACCEPT explicitly as a one-vector smoke and fix the path.

### (config-setup-canary) forum.toml is not gitignored — operator deployment config is commit-able  — *✓ confirmed*
- **Evidence:** /home/devuser/workspace/nostr-rust-forum/.gitignore (target/,dist/,pkg/,node_modules/,.wrangler/,.agentic-qe/,*.db,.env — no forum.toml); onboarding in forum.example.toml:5-8
- **Detail:** Onboarding is `cp forum.example.toml forum.toml; $EDITOR forum.toml`, but .gitignore lists .env and *.db and NOT forum.toml. A `git add .` after editing will stage the populated deployment config (admin static_pubkeys, hostnames, peer relays, issuer/agent pubkeys, native_pod URLs). No private secrets by design (custody model keeps secrets in env/Secrets), but deployment topology and any field an o
- **Decision:** FIX — add forum.toml (and forum.*.toml) to .gitignore; cheap and prevents accidental config commits.

### (config-setup-canary) Dead dependencies in nostr-bbs-config (url, schemars, serde_json, proptest)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-config/Cargo.toml:15-24 (url,serde_json,schemars,proptest); grep of src confirms no url::/JsonSchema/serde_json/proptest usage
- **Detail:** url, schemars and serde_json are declared dependencies but never used in src (no `use url`/`url::`; no JsonSchema derive despite schemars; no serde_json calls), and the proptest dev-dependency has no property tests. Beyond build bloat, the unused `url` and `schemars` are the smoking gun for two abandoned intents: robust URL parsing (replaced by the prefix-match bypass) and JSON-schema export for t
- **Decision:** FIX — remove the unused deps, or actually use url (for the prefix-bypass fix) and schemars (schema export).

### (core-protocol) process_kind4_event decrypts and trusts sender identity without verifying the event  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-core/src/gift_wrap.rs:500-514 (process_kind4_event: kind gate only, then nip04_decrypt on event.pubkey/event.content, no verify_event)
- **Detail:** process_kind4_event checks kind == 4 and then NIP-04-decrypts using event.pubkey as the sender for the ECDH, returning the plaintext. It never calls verify_event, so callers that treat event.pubkey as an authenticated sender (or key any state on it) are trusting an unverified field. As with the gift-wrap case the NIP-04 ECDH partially binds the sender pubkey, but skipping id/signature verification
- **Decision:** FIX — call verify_event_strict(event) before decrypting/returning, or clearly document that the caller must verify and that only the decrypted bytes (not event metadata) are trustworthy.

### (core-protocol) types.rs is a dead/divergent parallel event type system (EventId::compute uses kind:u32, PublicKey::from_hex skips curve validation)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/src/types.rs:36-54 (EventId::compute, kind:u32) vs crates/nostr-bbs-core/src/event.rs:78-91 (compute_event_id, kind:u64); types.rs:110-131 (PublicKey::from_hex/from_bytes, no VerifyingKey validation); lib.rs:80 re-exports only EventId/Tag/Timestamp
- **Detail:** types.rs defines a second EventId/PublicKey/Signature/Tag/Timestamp stack independent of the canonical event.rs path. EventId::compute canonicalises with kind: u32 whereas the authoritative compute_event_id uses kind: u64 — a silent divergence if this path were ever used for verification. types::PublicKey::from_hex validates only length+hex and does NOT check the bytes are a valid secp256k1 point
- **Decision:** DELETE the unused parallel types (or reconcile kind to u64 and add curve validation) so there is one canonical event/pubkey representation.

### (core-protocol) to_upstream_builder truncates event kind > u16 in release builds (debug_assert only)  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-core/src/event.rs:281-302 (debug_assert!(self.kind <= u16::MAX) then Kind::from(self.kind as u16))
- **Detail:** UnsignedEvent stores kind: u64 and compute_event_id hashes the full u64, but to_upstream_builder converts via Kind::from(self.kind as u16). The out-of-range guard is a debug_assert!, compiled out in the release Worker builds. A kind > 65535 on the upstream signing path (sign_event_upstream / to_upstream_builder) is silently truncated, producing an event whose kind (and thus id) diverges from what
- **Decision:** FIX — make to_upstream_builder / sign_event_upstream return Result and hard-error on kind > u16::MAX instead of a debug-only assert.

### (core-protocol) NIP-98 verification accepts only padded STANDARD base64 and does not normalise pubkey case  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-core/src/nip98.rs:54 (STANDARD engine), :434 (BASE64.decode), :446 (pubkey len/hex check, no lowercase normalisation), :503 (token.pubkey = event.pubkey verbatim)
- **Detail:** verify_token_full decodes the token with base64 STANDARD (padded) only; NIP-98 tokens produced with unpadded or URL-safe base64 (used by some JS clients) will fail as Base64 errors — an interop gap. Separately, the pubkey format check accepts uppercase hex (hex::decode is case-insensitive) and the returned Nip98Token.pubkey is passed through verbatim; consumers doing case-sensitive equality (e.g.
- **Decision:** IMPROVE — try STANDARD then STANDARD_NO_PAD/URL_SAFE on decode, and normalise the verified pubkey to lowercase before returning.

### (core-protocol) NIP-59 seal/wrap timestamps jitter into the future; spec recommends past-only  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-core/src/gift_wrap.rs:108-125 (randomized_timestamp: `add` branch returns now.saturating_add(offset))
- **Detail:** randomized_timestamp adds OR subtracts the jitter (now +/- 48h). NIP-59 recommends tweaking the seal/gift-wrap created_at only into the PAST (up to ~2 days). Future timestamps can trip relay created_at sanity limits or interact badly with NIP-40 expiration and client sorting, causing gift wraps to be dropped by some relays.
- **Decision:** IMPROVE — always subtract (past-only jitter) to match the NIP-59 recommendation and avoid future-timestamp relay rejections.

### (core-protocol) compute_event_id relies on serde_json string escaping, which diverges from strict NIP-01 for raw control characters  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-core/src/event.rs:78-91 (compute_event_id uses serde_json::to_string on the canonical tuple)
- **Detail:** compute_event_id serialises the canonical [0,pubkey,created_at,kind,tags,content] tuple with serde_json. serde_json escapes control chars outside the NIP-01 named set (\n\r\t\b\f\"\\) as \u00XX, whereas strict NIP-01 says all other characters MUST be emitted verbatim. In practice this matches rust-nostr (which the kit cross-verifies against via to_upstream().verify()) and nostr-tools JSON.stringif
- **Decision:** ACCEPT (document) — matches rust-nostr/nostr-tools; note the control-char edge in module docs rather than hand-rolling a NIP-01 serializer.

### (pod-worker) Blocktrails single-use-seal anchor written from unverified caller input  — *~ adjusted*
- **Evidence:** crates/nostr-bbs-pod-worker/src/pod_git_anchor.rs:199-222 (build_blocktrails — only length check, no txo verification), pod_git_anchor.rs:365-421 (bootstrap_pod_identity_and_trail takes vout/genesis_txo by value and writes them unverified)
- **Detail:** build_blocktrails / bootstrap_pod_identity_and_trail accept a caller-supplied `vout` and `genesis_txo` (TxoEntry{txid, vout}) and write them into blocktrails.json as a BIP-341 single-use-seal UTXO chain, enforcing only the structural invariant `states.len() == txo.len()`. Nothing verifies that the txo exists on-chain, is unspent, is a valid single-use seal, or actually commits to the genesis commi
- **Decision:** FIX (when wiring the native tier) — verify the seal txo before emitting blocktrails.json (existence/unspent check against a chain source, and a binding between the seal and the genesis commit SHA), or downgrade the artifact's documented mea

### (pod-worker) Provisioned container ACLs name the pod root ('./' → '/') instead of their own container  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/provision.rs:183-192 (root uses ./ ), 206-221 (public_acl accessTo/default = ./), 250-259 (private), 273-288 (inbox), 302-316 (profile), 331-339 (settings); normalize collapse at solid-pod-rs alpha.3 evaluator.rs:63-77
- **Detail:** Every container ACL provision_pod writes (root, public, media/public, private, inbox, profile, settings) uses `acl:accessTo` and `acl:default` of `"./"`, which the evaluator's normalize_path collapses to `"/"` (the pod root) rather than the container the sidecar governs. e.g. the `/public/.acl` foaf:Agent Read grant literally names `/`, not `/public/`. It happens to produce correct results ONLY be
- **Decision:** FIX — emit each authorization's accessTo/default as the container's own absolute pod-relative path (e.g. `/public/`, `/private/`) rather than `./`, so grants are self-describing and robust to resolver changes.

### (pod-worker) Native git-pod tier seeds no WAC ACL; CF private-container confidentiality model not reproduced on the clone-able repo  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/pod_git_anchor.rs:365-421 (writes did/gitmark/blocktrails only, no ACL seeding) vs provision.rs:182-351 (CF tier seeds root/public/private/inbox/profile/settings ACLs); git.rs:50-67 (.git/ blocked)
- **Detail:** The CF provision.rs seeds a full WAC ACL tree (owner-only root, public/private/inbox carve-outs). The native pod_git_anchor tier writes only agent.did.json, gitmark.json, blocktrails.json and the untracked privkey — no `.acl` — and exposes the pod as an externally-pullable (world-clone) git repo. The private/ container confidentiality semantics of the CF tier are therefore not enforced on the nati
- **Decision:** FREEZE/FIX — document that the native git tier is public-only, or seed an equivalent server-side access-control layer before storing any owner-private data in a git-backed pod.

### (pod-worker) is_dot_git_path only blocks root-level /.git/ ; nested '.git' segments not caught  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-pod-worker/src/git.rs:52-55 (is_dot_git_path — starts_with("/.git/") only), invoked once at lib.rs:688-690
- **Detail:** is_dot_git_path guards only `resource_path.starts_with("/.git/")` (and exact `/.git`). A nested path such as `/subdir/.git/config` is not matched. Impact is low: on the CF/R2 tier there is no real .git directory (such a path is just a user's own stored object in their own pod, served with the CSP-sandbox/nosniff headers), and on native the git-http-backend only serves the configured repo (a nested
- **Decision:** FIX — reject any path segment equal to `.git` (e.g. split on '/' and check each segment), not just a root-anchored prefix.

### (preview-search-ascii) /ascii returns attacker-influenced content as text/html without nosniff or CSP  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-preview-worker/src/lib.rs:234-241 (html_response sets only Content-Type/X-Cache), :459-461 (ASCII HTML served)
- **Detail:** html_response serves the rendered ASCII fragment as Content-Type: text/html directly from the worker origin. The body is correctly escaped so it is not itself an XSS vector, but there is no X-Content-Type-Options: nosniff and no Content-Security-Policy on an endpoint that emits HTML derived from an attacker-supplied image — defence in depth is missing for a public HTML-returning route.
- **Decision:** FIX — add X-Content-Type-Options: nosniff and a restrictive CSP (e.g. default-src 'none'; style-src 'unsafe-inline' if needed) to the /ascii response headers.

### (preview-search-ascii) og:image is loaded unproxied by the forum-client (viewer IP/UA tracking + client resource abuse)  — *✓ confirmed*
- **Evidence:** og:image passthrough crates/nostr-bbs-preview-worker/src/lib.rs:330-341 (image field echoed); direct client <img> crates/nostr-bbs-forum-client/src/components/link_preview.rs:183-191 (src=src)
- **Detail:** The preview worker returns the raw og:image URL (attacker-controlled via their page meta), and the forum-client renders it directly in a client-side <img src=src>. Every viewer's browser therefore fetches an attacker-chosen URL when a post scrolls into view, leaking each viewer's IP/User-Agent/timing to the attacker and allowing a huge-image resource-abuse on the client. This contradicts the proje
- **Decision:** ACCEPT or FIX — either document this as a known tradeoff or proxy the og:image through the worker (it already has an SSRF-guarded fetch path) before handing a URL to the client.

### (preview-search-ascii) Search worker multiplexes rate-limit counters and id↔label mapping onto one KV namespace; limiter is non-atomic/fail-open  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-search-worker/src/lib.rs:505 (rate limit on SEARCH_CONFIG) vs :179-190 (mapping persisted to SEARCH_CONFIG); non-atomic fail-open limiter crates/nostr-bbs-rate-limit/src/lib.rs:39-60; contrast dedicated binding crates/nostr-bbs-preview-worker/src/lib.rs:519
- **Detail:** check_rate_limit is called with the SEARCH_CONFIG KV binding — the same namespace persist_store writes the id↔label mapping into ({store_key}:mapping) — whereas the preview worker uses a dedicated RATE_LIMIT KV. Prefixes (rl:{ip}:{bucket} vs nostr-bbs.rvf:mapping) do not collide, so this is not a correctness bug today, but mixing rate-limit write traffic into the config KV is inconsistent and frag
- **Decision:** FIX — give the search worker a dedicated RATE_LIMIT KV binding (matching the preview worker) and track the non-atomic limiter as a known abuse-control gap.

### (relay-ratelimit) auto_whitelist is dead code — the documented first-user-is-admin / first-kind-0 auto-registration never runs in the relay  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/storage.rs:336 (definition), storage.rs:373 (internal log); grep across src/ and tests/ finds no call site
- **Detail:** auto_whitelist (with its 'first-user-is-admin' promotion and members-cohort auto-registration) is defined but never called from anywhere in the relay crate's src/ or tests/. The only match outside the definition is its own internal console_log. Its security-relevant behaviour (auto-granting admin/all-zones to the first registrant, auto-admitting anyone who posts a first kind-0) therefore does not
- **Decision:** DELETE the dead function (and its misleading first-user-is-admin comment), or FINISH by wiring it into the kind-0 ingest path if auto-registration is actually intended — but confirm the auth-worker isn't the real owner of registration first

### (relay-ratelimit) D1 replay store fails OPEN when statement meta is unavailable  — *✓ confirmed*
- **Evidence:** crates/nostr-bbs-rate-limit/src/replay.rs:37-40 (`_ => Ok(true)`); contrast core semantics nostr-bbs-core/src/nip98.rs:85-93 and 582-588
- **Detail:** seen_or_record must return Ok(true) only on genuine first-seen. The D1 impl returns Ok(rows_written>0) on the happy path but falls through to Ok(true) whenever result.meta() is Ok(None) or Err. Ok(true) means 'first observation → allow', so if D1 omits/erros meta, a replayed NIP-98 token is accepted instead of rejected — converting what verify_nip98_with_replay treats as a fail-closed backend erro
- **Decision:** FIX — return Err on meta unavailability (fail closed) so the caller surfaces Nip98Error::ReplayBackend rather than admitting a possible replay.

### (relay-ratelimit) In-memory per-IP rate_limits map grows unbounded on a continuously-busy relay  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/broadcast.rs:141-154 (entry created/retained, key never removed); mod.rs:297-304 (alarm clears only when sessions empty)
- **Detail:** check_rate_limit inserts a HashMap entry keyed by source IP for every EVENT frame (created before the whitelist check, so even rejected junk events from any connected client create an entry). retain() trims timestamps but leaves the (IP → empty Vec) key in place. The map is only cleared by the idle alarm, which fires solely when sessions is empty. A relay that is never fully idle accumulates one e
- **Decision:** FIX — evict IP entries whose timestamp vector is empty after retain(), or periodically prune stale keys independent of full idle.

### (relay-ratelimit) NIP-42 challenge is regenerated (never re-sent) after hibernation, breaking first-time AUTH for gated reads  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-relay-worker/src/relay_do/session.rs:96,116 (fresh generate_challenge on recovery, not sent); handle_auth challenge equality check nip_handlers.rs:808-820
- **Detail:** On connect the client receives challenge C1. If the DO hibernates before the client sends AUTH, recover_session sets session.challenge to a freshly generated C2 that is never transmitted (no AUTH frame is re-sent on recovery). handle_auth then requires the response's challenge tag to equal the session challenge (now C2), so the client's AUTH carrying C1 is rejected as 'challenge mismatch'. Already
- **Decision:** FIX — persist the originally-sent challenge alongside ws_sub/ws_auth and restore it on recovery (or re-send AUTH with the regenerated challenge on recovery) so post-hibernation first-time AUTH succeeds.

### (stubs-adrs) nostr-bbs-mesh is an empty scaffold crate published as 1.0.0-beta.3 with no implementation  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-mesh/src/lib.rs:14-22; crates/nostr-bbs-mesh/Cargo.toml:3; docs/architecture.md:182
- **Detail:** The mesh crate (lib.rs:14-22) is explicitly 'Scaffold only — federation is designed, not shipped': no MeshTransport implementation exists anywhere, and it is confirmed NOT a dependency of nostr-bbs-relay-worker. Yet it carries version 1.0.0-beta.3 (Cargo.toml:3) and is in the publish set, so crates.io ships a beta crate of nothing but traits. It cites ADR-073 (lib.rs, architecture.md:182), which i
- **Decision:** FREEZE — mark publish=false (or 0.0.x pre-release) until a transport ships, so a 1.0.0-beta of an empty crate is not published; keep the scaffold documented.

### (stubs-adrs) Stale solid-pod-rs version-pin comments contradict the actual pin (0.5.0-alpha.3)  — *· unverified (plausible)*
- **Evidence:** Cargo.toml:123-141; docs/adr/ADR-086-nip05-pod-federation.md:160-166; crates/nostr-bbs-pod-worker/src/export.rs:7; crates/nostr-bbs-core/src/did.rs:13,138
- **Detail:** Root Cargo.toml:141 pins solid-pod-rs = 0.5.0-alpha.3, but the comment block immediately above (Cargo.toml:123-140) narrates 0.4.0-alpha.3 for the core flag, and 'Registry dep: 0.4.0-alpha.17 is published from git tag v0.4.0-alpha.17... the alpha.15 aliasing... is resolved'. ADR-086 §8 and export.rs:7 further cite 'alpha.11'. None of these match the live 0.5.0-alpha.3 pin. A reader cannot tell whi
- **Decision:** FIX the comments to describe the real 0.5.0-alpha.3 pin, and add a closeout task to bump the pin once the solid-pod-rs closeout/2026-07-03 fixes publish (verify the did_nostr_types binding change lands).

### (stubs-adrs) content_negotiation silently downgrades Turtle requests to JSON-LD (TODO: convert to Turtle)  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-pod-worker/src/content_negotiation.rs:76-82
- **Detail:** content_negotiation.rs:79-82: a client sending Accept: text/turtle for a JSON-LD-stored resource is served JSON-LD with the media type coerced to JSON-LD ('return JSONLD.to_string(); // TODO: convert to Turtle'). Solid/LDP clients that request Turtle get a non-Turtle body, an interop gap. (The adjacent HTML branch, by contrast, correctly hardens against content-type confusion — that part is good.)
- **Decision:** FINISH (wire a JSON-LD→Turtle converter) or ACCEPT with an honest 406/Vary response rather than mislabelling the body as JSON-LD; document the limitation in the pod content-negotiation contract.

### (stubs-adrs) ADR-101 accepted-but-deferred leaves device-key users with no DMs; ADR-105 passkey governance-write attribution gap deferred  — *· unverified (plausible)*
- **Evidence:** docs/adr/ADR-101-multi-device-dm-delivery.md:3; docs/adr/ADR-099-revocable-device-keys.md:4; docs/adr/ADR-105-bbs-door-games-and-write-architecture.md:§6-amendment; docs/diagrams/00-anomaly-register.md:O6
- **Detail:** ADR-101 (Multi-device NIP-17 DM delivery) is 'Accepted (implementation deferred — ADR-099 phase 2)': a user who onboards a phone with a device key sees the full forum but receives no DMs on that device (gift-wraps are encrypted to the master). It is gated behind DEVICE_KEYS_ENABLED (default off) so latent, but it is a documented functional gap, related to anomaly O6 (NIP-07 users get a silent no-o
- **Decision:** FREEZE (documented) — before enabling DEVICE_KEYS_ENABLED, either implement ADR-101 multi-wrap send or surface a clear 'no DMs on this device' UI warning to close O6; keep the ADR-105 passkey-attribution note tracked.

### (stubs-adrs) Minor closeout debt: nickname TODOs, unjustified RUSTSEC ignores, and stale ADR-089 link in the git 501 body  — *· unverified (plausible)*
- **Evidence:** crates/nostr-bbs-forum-client/src/pages/dm_chat.rs:191; crates/nostr-bbs-forum-client/src/components/profile_modal.rs:48; deny.toml:14-22; crates/nostr-bbs-pod-worker/src/git.rs (git_not_implemented docs URL → ADR-089)
- **Detail:** Three small residual items. (1) forum-client TODO(nicknames) in dm_chat.rs:191 and profile_modal.rs:48 defer showing the raw npub as a technical fingerprint beneath the nickname — a verification affordance users explicitly want. (2) deny.toml:17 TODO: five RUSTSEC ignores lack per-crate justification and a review date. (3) git.rs git_not_implemented returns a 'docs' link pointing at ADR-089, which
- **Decision:** FINISH the small items — render the raw npub, add justification+review-date to each RUSTSEC ignore, and repoint the git 501 docs link to ADR-093 (the superseding decision).


## Verifier-surfaced misses (analyst gaps caught by the adversarial pass)

- [auth-worker] admin_set() also drops the RELAY_DB whitelist source, making finding #2 strictly broader than stated: moderation.rs:129-151 runs BOTH MEMBERS_ADMIN_LIST_SQL and WHITELIST_ADMIN_LIST_SQL against env.d1("DB"), but is_admin
- [auth-worker] Same admin-source divergence affects the relay whitelist table binding: WHITELIST_ADMIN_LIST_SQL is executed against the auth-worker's own DB binding (which does not own the whitelist table per admin.rs docs), so that ar
- [pod-worker] Partial-provisioning robustness gap (in-scope, minor): provision_pod writes the root container marker FIRST (provision.rs:137-147); if any subsequent R2 put (an ACL or type-index) fails, pod_exists() (checks only 'pods/{
- [pod-worker] Adjacent/likely-out-of-scope (flag for cross-dimension coverage, not a within-dimension miss): the pod-worker crate also serves GET /.well-known/did/nostr/{pubkey}.json (lib.rs:537-555 → build_did_nostr_document:367-383
- [core-protocol] Completeness gap in Finding 2, not a new class: auth-worker handle_report (moderation.rs:287-364) also calls validate_moderation_event (309) with NO verify_event on body.event before inserting into mod_reports; it only c
- [core-protocol] Adjacent, out-of-dimension (forum-client, not nostr-bbs-core) but material: forum-client process_kind4_event (dm/mod.rs:685-717) decrypts kind-4 legacy DMs via signer.nip44_decrypt (NIP-44), re-introducing the exact 'nip
- [core-protocol] No hand-rolled-crypto miss to report (positive): re-verified nip44.rs and nip04.rs are thin adapters delegating to rust-nostr 0.44 (nostr::nips::nip44/nip04), and verify_event_strict does a real curve check (VerifyingKey
- [relay-ratelimit] P1 (MATERIAL, top miss) — kind-1059 sealed-DM read/COUNT gate is bypassable by omitting `kinds`. gate_kind_1059_filters (nip_handlers.rs:877-899) sets needs_kind_1059 only when a filter's `kinds` array explicitly contain
- [relay-ratelimit] P2 (MATERIAL) — ordinary tag filters are also unindexed full-table scans, broadening F1. build_filter_conditions compiles #e/#p/#t filters to `instr(tags, ?) > 0` (filter.rs:159-164) with no index on the tags column, so
- [relay-ratelimit] P3 (minor) — capability-advertisement drift feeding F2's 'false NIP-11' theme: /health advertises nips [.. ,17, ..] and omits 56 (lib.rs:239) while NIP-11 supported_nips advertises 56 and deliberately omits 17 (nip11.rs:
- [relay-ratelimit] P3 (minor) — write amplification on the unrate-limited REQ path: handle_req persists subscriptions to DO transactional storage on every REQ via save_subscriptions (nip_handlers.rs:589), so a REQ storm forces one billable
- [preview-search-ascii] Unauthenticated /search loads the ENTIRE R2 vector-store blob into isolate memory on every request (handle_search -> load_store, lib.rs:288 -> :135-159, bucket.get(store_key).body().bytes()), plus a KV mapping read (:300
- [preview-search-ascii] The P0 prefix-match (is_pod_url) is broader than the analyst's subdomain-suffix example: because it is a raw starts_with, the userinfo form 'https://<pod_api>@evil.com/x.png' also matches (real host evil.com) and is extr
- [clients-mesh] Same byte-index-vs-char-boundary panic class as Finding 2 exists at ADDITIONAL attacker-content render sites NOT covered by Finding 2's evidence/fix scope: bookmarks_modal.rs:72-73 (`if content.len() > 120 { &content[..1
- [config-setup-canary] nostr-bbs-config itself (version 1.0.0-beta.3) also lacks `publish = false` — unlike the canary which has it (Cargo.toml). The library whose entire validation layer is dead would publish to crates.io/docs.rs still advert
- [config-setup-canary] The whole [webauthn] config section is decorative for the security-critical WebAuthn origin binding: at runtime auth-worker webauthn.rs:99 (expected_origin_required(env), fail-closed) and pod-worker lib.rs:727 both sourc
- [config-setup-canary] Operator-facing forum.example.toml:11 repeats the false 'The worker crates load it at startup (`nostr_bbs_config::load_from_path`)' claim — a second, more damaging location than lib.rs:5-7, since it is the exact file ope
- [config-setup-canary] Pubkey hex checks (validate.rs:76, 178) use is_ascii_hexdigit(), which accepts uppercase/mixed-case, but Nostr pubkeys are canonically lowercase 64-hex and runtime comparisons (e.g. auth-worker admin match) are case-sens
- [stubs-adrs] PHANTOM STUB FILES (material, this dimension): pod-worker Cargo.toml:19-20 comment claims the solid-pod-rs-phase1 feature 'unlocks the stub modules in src/{key_provisioning,export,nip05_endpoint}.rs', and consumer-surfac
- [stubs-adrs] MINOR — register/body status contradiction for ADR-105: docs/adr/README.md register lists ADR-105 as 'Accepted (write-path deferred)', but the ADR-105 body was amended 2026-07-03 to state 'The write-path is live, not def
---

## Consumption boundary — solid-pod-rs (Opus deep-dive, verified)

**Headline: the forum is structurally IMMUNE to all four solid-pod-rs `0.5.0-alpha.3` audit issues.** It links only the single `solid-pod-rs` crate (`core` feature — no `-server`/`-nostr`/`-git`/`-idp`) and reimplements provisioning, WAC enforcement, and did:nostr itself:

- **P1-d owner-lockout** — the forum never calls `solid_pod_rs::provision::provision_pod`; its own `provision.rs:182-203` unconditionally seeds the owner root `.acl` (Read+Write+Control) plus correct per-container ACLs. No lockout, no world-open.
- **P1-l / P0-3 / P0-4** — these are `solid-pod-rs-server` HTTP handlers; the forum ships its own Cloudflare-Workers request path.
- **P1-m alsoKnownAs impersonation** — `resolve_nostr_to_webid` lives in `solid-pod-rs-nostr` (`did-nostr` feature, **not compiled**); the forum derives WebIDs deterministically via `webid_url(pod_api, hex)`.

**Re-pin to ≥ alpha.4 is hygiene only, not security-required.** One conditional trigger: if the native/agentbox tier is ever wired to `solid_pod_rs::provision::provision_pod`, it MUST re-pin **and** pass `root_acl` (today the native git path writes no root ACL).

### P2-1 · Forum's own `.acl` GET discloses the authorization graph to Read-holders (replicates upstream P0-3) — *confirmed*
- **Evidence:** `crates/nostr-bbs-pod-worker/src/lib.rs:1435-1455` — `handle_acl_request` GET grants read on `acl:Read` **OR** `acl:Control` (not Control-only). Write side *is* correctly Control-elevated (`lib.rs:1497-1510` PUT, `1613-1626` DELETE). Public-read containers seeded at `provision.rs:205-232,301-328`.
- **Impact:** on any `foaf:Agent`-readable container (`/public/`, `/media/public/`, `/profile/`), anyone can `GET <container>/.acl` and read every WebID, delegate `did:nostr`, and rule — the same info-disclosure the upstream closeout fixes as P0-3, but in the forum's own handler (a re-pin does not touch it).
- **Decision: FIX** — require `acl:Control` on the parent for `.acl` GET/HEAD, mirroring the write-side coercion the forum already has.

### Low-priority (P3)
- `verify_webid_tag` substring match (bounded — the WAC `agent_uri` derives from the NIP-98-verified pubkey, not the tag; present on both versions). FIX in forum/core, low priority.
- did:nostr endpoint answers for any 64-hex pubkey — but `alsoKnownAs` is derived deterministically from the queried key (self-consistent, not a false binding). ACCEPT; optionally 404 unknown pods.
- git-pod blocktrail anchors are caller-asserted, not verified on-chain (native-only, `cfg(not(wasm32))`, never gates auth). FREEZE (documented).
