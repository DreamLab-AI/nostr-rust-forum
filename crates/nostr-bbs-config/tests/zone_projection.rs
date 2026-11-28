//! The `ZONE_CONFIG` projection of the example config, byte for byte.
//!
//! The deploy pipeline serialises `[[zones]]` to JSON and hands that string to
//! the relay, auth and pod workers and to both clients. The fixture was
//! captured from the schema before ADR-2037 added `channels`; it must not
//! change when no zone pins a channel, or every existing deployment's
//! projection (and the website's mirror check) would drift.

use std::path::PathBuf;

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../forum.example.toml")
}

#[test]
fn example_zones_project_exactly_as_before_channel_pins() {
    let cfg = nostr_bbs_config::load_from_path(example_path()).expect("example config loads");
    let json = serde_json::to_string(&cfg.zones).expect("zones serialise");
    assert_eq!(json, include_str!("fixtures/forum-example-zones.json"));
}

/// Every optional zone field set (none of them `channels`): the projection
/// round-trips to the same bytes the schema produced before ADR-2037.
#[test]
fn a_fully_specified_zone_projects_exactly_as_before_channel_pins() {
    let src = include_str!("fixtures/full-zone.json").trim();
    let zone: nostr_bbs_config::schema::Zone = serde_json::from_str(src).expect("zone parses");
    assert_eq!(serde_json::to_string(&zone).unwrap(), src);
}
