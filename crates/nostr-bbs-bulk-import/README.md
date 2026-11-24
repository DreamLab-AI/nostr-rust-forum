# nostr-bbs-bulk-import

Offline bulk import of an external chat archive (Keybase today; Discord, Slack or Matrix through
new adapters) into a nostr-bbs forum deployment. Library plus the `nostr-bbs-import` CLI.

* Source adapters write a versioned JSONL intermediate format (`docs/bulk-import/FORMAT.md`).
* Identity planning: fresh keys, per-person archive keys aliased to proven live keys, merges,
  drops, deferred operator history; an atomic, refuse-to-change keystore.
* One topic per source channel under archivist-signed roots, in the forum client's own tag shapes.
* Content-addressed image optimisation (ImageMagick under a deny-all policy, metadata stripped).
* A local D1 build with full ingest parity, resumable and idempotent through a ledger.
* Glue for `nostr-bbs-zone-migrate` offline sealing, the sealed-search hand-off, and an upload
  plan (allowlisted dump, R2 object list, cutover runbook) that the tool never runs.

It makes no network calls. It is the generalised successor of the Node migrator written for the
Keybase pilot.

```sh
nostr-bbs-import adapt keybase --in ~/archive/myteam --work W
nostr-bbs-import plan --work W --zone zone2      # then edit identities.json / structure.json
nostr-bbs-import keys --work W ensure
nostr-bbs-import media --work W
nostr-bbs-import build --work W --d1 relay.sqlite
nostr-bbs-import seal-prep --work W --d1 relay.sqlite --relay ws://127.0.0.1:8787
nostr-bbs-import upload-plan --work W --d1 relay.sqlite
```

Documentation: `docs/bulk-import/README.md` (operator guide and runbook), `FORMAT.md`,
`SECURITY.md`, `DESIGN.md`, and the crate's rustdoc.

`publish = false`: the keystore, ledger and plan files are formats private to this kit.

Licence: AGPL-3.0-only (see the repository's `LICENSE`).
