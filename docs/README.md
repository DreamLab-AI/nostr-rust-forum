# nostr-rust-forum — documentation index

Back to the top-level project overview: [../README.md](../README.md).

This directory holds the deeper reference material for the forum kit.

- [architecture.md](architecture.md) — architecture overview, request lifecycle, crate breakdown, NIP coverage, calendar projection
- [consumer-surface-map.md](consumer-surface-map.md) — who consumes the governance surface today
- [phase1-impact-assessment.md](phase1-impact-assessment.md) — phase-1 impact assessment
- [adr/](adr/) ([index](adr/README.md)) — architecture decision records
- [prd/](prd/) — product requirement docs (BBS client, gap-close forum, zone-bound PWA)
- [ddd/](ddd/) — domain-driven-design bounded-context models
- [diagrams/](diagrams/) — auth, governance, pod/ACL, and relay-admission flow diagrams
- [bulk-import/](bulk-import/README.md) — offline bulk import of an external chat archive (Keybase; Discord/Slack/Matrix via adapters) into a deployment: [operator guide](bulk-import/README.md), [intermediate format](bulk-import/FORMAT.md), [security](bulk-import/SECURITY.md), [design](bulk-import/DESIGN.md); crate `nostr-bbs-bulk-import`, CLI `nostr-bbs-import`
- [runbooks/](runbooks/) — operator procedures: disaster recovery, phased deploy, [relay deletion and tombstones](runbooks/relay-deletion-and-tombstones.md)
- [sprint/](sprint/) — sprint and milestone notes
- [audit/](audit/) — audit records
