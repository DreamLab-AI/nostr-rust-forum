// crates/nostr-core/tests/upstream_vectors/all_fixtures.rs
//! Forum-side L1 reference-vector wiring for all 13 fixtures.
//!
//! One test per fixture; each loads the fixture (or skips if absent) and
//! asserts the metadata block matches the expected spec. Substrate-side
//! crypto/wire validation hooks are stubbed pending PRD-009 F26 absorption
//! of the kit into VisionClaw — at that point these tests gain real
//! assertions against `nostr-core` types.

#[path = "mod.rs"]
mod loader;
use loader::{assert_meta_block, try_load_fixture};

macro_rules! fixture_test {
    ($name:ident, $file:literal, $spec:literal, $min_vectors:expr) => {
        #[test]
        fn $name() {
            let Some(f) = try_load_fixture($file) else {
                eprintln!(
                    "fixture {} not found in tests/fixtures/ — skipping; run scripts/sync-fixtures.sh first",
                    $file
                );
                return;
            };
            assert_meta_block(&f, $spec);
            let vectors = f["vectors"].as_array().or_else(|| {
                // nip44-v2 has nested vectors; fall back to the valid bucket count
                f["vectors"]["valid"]
                    .as_object()
                    .map(|_| f["vectors"]["valid"]["get_conversation_key"].as_array())
                    .unwrap_or(None)
            });
            if let Some(arr) = vectors {
                assert!(
                    arr.len() >= $min_vectors,
                    "fixture {} must have >= {} vectors",
                    $file,
                    $min_vectors
                );
            }
        }
    };
}

fixture_test!(
    nip01_events_load_and_validate,
    "nip01-events.json",
    "NIP-01",
    11
);
fixture_test!(nip04_dm_load_and_validate, "nip04-dm.json", "NIP-04", 4);
fixture_test!(
    nip19_bech32_load_and_validate,
    "nip19-bech32.json",
    "NIP-19",
    12
);
fixture_test!(
    nip26_delegation_load_and_validate,
    "nip26-delegation.json",
    "NIP-26",
    5
);
fixture_test!(nip44v2_load_and_validate, "nip44-v2.json", "NIP-44", 30);
fixture_test!(
    nip59_gift_wrap_load_and_validate,
    "nip59-gift-wrap.json",
    "NIP-59",
    6
);
fixture_test!(
    nip98_tokens_load_and_validate,
    "nip98-tokens.json",
    "NIP-98",
    6
);
fixture_test!(
    bip340_load_and_validate,
    "bip340-schnorr.json",
    "BIP-340",
    19
);
fixture_test!(rfc8785_load_and_validate, "rfc8785-jcs.json", "RFC 8785", 6);
fixture_test!(
    multibase_load_and_validate,
    "multibase.json",
    "Multibase",
    27
);
fixture_test!(
    did_doc_load_and_validate,
    "did-doc-conformance.json",
    "ADR-125",
    9
);
fixture_test!(
    is_envelope_load_and_validate,
    "is-envelope-v1.json",
    "ADR-075",
    11
);
fixture_test!(
    mesh_federation_load_and_validate,
    "mesh-federation.json",
    "ADR-073",
    9
);
