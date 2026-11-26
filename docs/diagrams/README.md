# Diagrams for this repository live in VisionFlow

The citation-verified diagrams for nostr-rust-forum are kept in the VisionFlow
estate corpus, at
[`docs/diagrams/nostr-rust-forum/`](https://github.com/DreamLab-AI/VisionFlow/tree/main/docs/diagrams/nostr-rust-forum)
in [DreamLab-AI/VisionFlow](https://github.com/DreamLab-AI/VisionFlow).

**Why.** The estate keeps one diagram corpus, so every repository's diagrams are
reported and audited in one place. Each topic there cites the code it was drawn
from as `path:line` and is stamped with the revision it was verified against; the
corpus generator checks those citations before a topic is accepted. A second,
separately maintained copy here would have to be kept in step by hand, so the
kit's own diagram files were removed on 2026-11-22.

**Open findings stay here.** The kit's open security and behavioural findings are
recorded, with owners and dispositions, in
[`docs/security/known-findings.md`](../security/known-findings.md). Cite the KF id
as the primary reference; VisionFlow's NF-10
(`10-invariants-and-anomaly-register.md`) carries the diagrammed context for the
former register ids O12 to O26.

## Where the removed files went

The five files removed from this directory are in git history (last at `fd31193`).
Their content maps to these VisionFlow topics:

| Removed file | VisionFlow topics |
|---|---|
| `00-anomaly-register.md` (O1 to O26, R1 to R13) | NF-10 (register, invariants, doc drift) |
| `relay-event-admission.md` | NF-03 (admission, AUTH, trust, NIP-09 gate), NF-11 (Durable Object internals, ModCache, hibernation, broadcast, `process_deletion`) |
| `client-onboarding-and-messaging.md` | NF-05 (forum client), NF-22 (recovery sheet and `/connect`), NF-20 (device keys), NF-27 (zone keys), NF-07 (preview and search) |
| `pod-acl-and-identity.md` | NF-04 (pod worker, ACL, delegation), NF-12 (key derivation) |
| `auth-governance-flows.md` | NF-02 (auth worker, NIP-98, device registry), NF-06 (agent control surface), NF-08 (stores and admin authority), NF-25 (membership lifecycle) |
