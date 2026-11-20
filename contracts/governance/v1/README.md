# Governance contract v1

The wire contract for the governance event kinds 31400-31405, rendered as data.
`nostr-bbs-core` (`crates/nostr-bbs-core/src/governance.rs`) is its only author;
these files are generated from it and never edited by hand.

| File | Content |
|------|---------|
| `<kind>-<name>.json` | One valid, fully populated, signed example of each kind, built with the crate's own types and validated by the crate's own validator. |
| `content-key-order-vectors.json` | Deliberately unsorted nested JSON inputs with the exact content text a producer must emit, plus one signed 31402 built from unsorted `fields` so an event id is pinned as well as the text. |
| `manifest.json` | The kinds and names, required and optional tags and content fields, every enum string the contract uses, and the numeric rules a producer must respect (for example `min_human_rationale_chars`). |

Fixed test keys and timestamps are used, so the files are reproducible.

## Content key order

Event content is part of the event id, so the same content must be the same
bytes in every build and every language. The rule for free-form JSON in
content (a 31402's `fields`, a 31401 or 31404 body, a 31403 decision body):

* write it compactly, with no whitespace;
* sort every object's keys, recursively, by UTF-16 code unit (RFC 8785 order,
  and the default order of a JavaScript `Array.prototype.sort()` on keys);
* keep array order;
* leave scalars as `serde_json` writes them. This is the key order of RFC 8785
  (JCS), not full JCS: number and string-escape text is not re-normalised, so
  keep numbers to forms both sides print identically (integers, short decimals).

Two limits follow, and a producer in another language must respect both:

* number text is not normalised. `serde_json` writes a float parsed from `1.0`
  as `1.0` where JavaScript's `JSON.stringify` writes `1`; exponent forms and
  integers above 2^53 also differ. Use integers below 2^53, or strings;
* keys that look like integers sort as text (`"10"` before `"9"`). A JavaScript
  object lists such keys first, in numeric order, whatever order they were
  inserted in, so sorting keys into a new object and calling `JSON.stringify`
  is not enough: write each object from its sorted key list.

A signature still verifies when these are broken, because each producer signs
its own bytes; what is lost is the same id for the same content.

Content that is a typed struct (`PanelDefinition`, `ActionRequest` at its top
level) keeps the struct's field declaration order, which is fixed in code and
is unchanged by this rule; only free-form values inside it are sorted.

Without this rule the order depended on whether any crate in the build enabled
`serde_json`'s `preserve_order` feature (Cargo unifies features across a
workspace), so a `-p` build and a `--workspace` build disagreed.
`nostr_bbs_core::governance::canonical_json_string` and
`serialize_canonical` implement it; `content-key-order-vectors.json` pins it.

## Who consumes it

Consumers that cannot link the Rust crate copy this directory verbatim. agentbox
(JavaScript) loads `manifest.json` through `management-api/lib/governance-contract.js`
and checks what it produces against these examples. Rust consumers such as
VisionClaw should depend on `nostr-bbs-core` directly instead.

## Regenerating

The test `governance_golden_files_match_the_crate` fails when any file is stale.
After an intended change to the contract:

```sh
UPDATE_GOVERNANCE_CONTRACT=1 cargo test -p nostr-bbs-core --test governance_contract_golden
```

Review the diff, commit it, and copy the directory to each consumer. A breaking
change belongs in a new `v2/` directory, not an edit to `v1/`.
