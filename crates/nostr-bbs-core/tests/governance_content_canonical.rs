//! Governance event content must not depend on JSON map ordering.
//!
//! `serde_json` keeps object keys sorted unless some crate in the build turns
//! on `preserve_order`, which Cargo unifies across a workspace. Free-form JSON
//! in event content (a proposal's `fields`, a status diff) would then be
//! written in insertion order, so the same event gets a different id in
//! different builds. This crate's dev-dependencies turn `preserve_order` on, so
//! these tests always run in the worse of the two builds.

use nostr_bbs_core::governance::ActionRequest;
use serde_json::{json, Map, Value};

fn request(fields: Value) -> ActionRequest {
    ActionRequest {
        fields,
        reasoning: Some("why".into()),
        context_url: None,
        risk_tier: None,
        confidence: None,
        task_properties: None,
        probe: None,
    }
}

/// Build an object by inserting the keys in the order given.
fn ordered(pairs: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), v.clone());
    }
    Value::Object(m)
}

#[test]
fn action_request_content_is_independent_of_field_insertion_order() {
    let a = request(ordered(&[
        ("zeta", json!(1)),
        ("alpha", ordered(&[("y", json!(true)), ("x", json!(null))])),
        (
            "list",
            json!([ordered(&[("b", json!(1)), ("a", json!(2))])]),
        ),
    ]));
    let b = request(ordered(&[
        (
            "list",
            json!([ordered(&[("a", json!(2)), ("b", json!(1))])]),
        ),
        ("alpha", ordered(&[("x", json!(null)), ("y", json!(true))])),
        ("zeta", json!(1)),
    ]));
    let ca = serde_json::to_string(&a).unwrap();
    let cb = serde_json::to_string(&b).unwrap();
    assert_eq!(ca, cb, "same fields, different insertion order");
    assert!(
        ca.starts_with(
            r#"{"fields":{"alpha":{"x":null,"y":true},"list":[{"a":2,"b":1}],"zeta":1},"reasoning":"why""#
        ),
        "{ca}"
    );
}
