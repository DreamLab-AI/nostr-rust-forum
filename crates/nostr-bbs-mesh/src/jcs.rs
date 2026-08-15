//! RFC 8785 JSON Canonicalization Scheme (JCS) — the subset required by the
//! IS-Envelope contract (ADR-075 §D5).
//!
//! ADR-075 mandates that every envelope is serialised with JCS *before* it
//! becomes the `content` of a kind-14 rumor, so that the outer kind-1059 event
//! id (SHA-256 over canonical event JSON) is stable across independent
//! encoders. Two encoders producing semantically identical envelopes must emit
//! byte-identical `content`, or the dedup primitive of ADR-075 §D12 breaks.
//!
//! # Scope and honesty about it
//!
//! This is a *faithful subset* of RFC 8785, not the whole specification:
//!
//! * **Object member ordering** — keys are sorted by their UTF-16 code units.
//!   For the ASCII keys used throughout the envelope (and virtually all JSON
//!   object keys in practice) UTF-16 order is identical to Unicode-scalar
//!   order, which is what Rust's `str` `Ord` gives us, so [`canonicalize`]
//!   sorts by `&str` comparison. Keys containing characters above the Basic
//!   Multilingual Plane (U+FFFF, i.e. those needing surrogate pairs in UTF-16)
//!   would sort differently under strict RFC 8785; the envelope never uses
//!   such keys and application `body` payloads are strongly discouraged from
//!   doing so. This limitation is deliberate and documented rather than hidden.
//! * **Numbers** — serialised via `serde_json`'s `Number` `Display`, which is
//!   canonical for the integers the envelope uses (`v`, `ttl`, timestamps).
//!   Arbitrary floating-point `body` values are *not* run through the full
//!   ECMAScript `Number.prototype.toString` shortest-round-trip algorithm; the
//!   envelope schema uses integers only, and callers are advised to keep
//!   floats out of canonicalised bodies.
//! * **Strings** — escaped by `serde_json`, which matches RFC 8785's RFC 8259
//!   minimal-escaping requirement (control characters and `"`/`\` only).
//! * **Whitespace** — none between tokens.
//!
//! The canonicaliser is dependency-free (operates on [`serde_json::Value`]) so
//! it compiles unchanged on `wasm32-unknown-unknown` for the Cloudflare Workers
//! target.

use serde_json::Value;

/// Canonicalise a [`serde_json::Value`] to an RFC 8785 (subset) JCS string.
///
/// Object keys are emitted in ascending `&str` order; there is no whitespace
/// between tokens; strings are minimally escaped. See the module docs for the
/// precise subset guarantees.
///
/// # Example
///
/// ```
/// use serde_json::json;
/// let v = json!({ "b": 1, "a": [3, 2, { "y": 1, "x": 2 }] });
/// assert_eq!(
///     nostr_bbs_mesh::jcs::canonicalize(&v),
///     r#"{"a":[3,2,{"x":2,"y":1}],"b":1}"#
/// );
/// ```
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Collect and sort keys. serde_json's Map is a BTreeMap by default
            // (already sorted) but may be an IndexMap if some crate in the
            // dependency graph enables `serde_json/preserve_order`; sorting
            // explicitly makes the canonical form independent of that feature
            // unification.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Emit a JSON string with RFC 8259 minimal escaping (matching RFC 8785).
///
/// Delegates to `serde_json` so the escaping rules stay identical to how the
/// rest of the stack serialises strings.
fn write_string(s: &str, out: &mut String) {
    // serde_json::to_string on a &str never fails and produces a correctly
    // escaped, double-quoted JSON string with the minimal escape set.
    let encoded = serde_json::to_string(s).expect("string serialization is infallible");
    out.push_str(&encoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_recursively() {
        let v = json!({ "b": 1, "a": { "z": 1, "a": 2 } });
        assert_eq!(canonicalize(&v), r#"{"a":{"a":2,"z":1},"b":1}"#);
    }

    #[test]
    fn no_whitespace_between_tokens() {
        let v = json!({ "list": [1, 2, 3], "s": "x" });
        assert_eq!(canonicalize(&v), r#"{"list":[1,2,3],"s":"x"}"#);
    }

    #[test]
    fn escapes_special_characters() {
        let v = json!({ "s": "a\"b\\c\n" });
        assert_eq!(canonicalize(&v), r#"{"s":"a\"b\\c\n"}"#);
    }

    #[test]
    fn stable_across_input_key_order() {
        let a = json!({ "one": 1, "two": 2, "three": 3 });
        let b = json!({ "three": 3, "one": 1, "two": 2 });
        assert_eq!(canonicalize(&a), canonicalize(&b));
    }

    #[test]
    fn preserves_array_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonicalize(&v), "[3,1,2]");
    }
}
