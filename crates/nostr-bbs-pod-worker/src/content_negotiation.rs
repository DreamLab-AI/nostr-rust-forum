//! Content negotiation for Solid pod resources.
//!
//! Supports JSON-LD (default), Turtle (text/turtle), and N-Triples.
//! JSON-LD is the native storage format. Other formats are derived on-the-fly.

/// Supported RDF content types in preference order.
pub const JSONLD: &str = "application/ld+json";
pub const JSON: &str = "application/json";
pub const TURTLE: &str = "text/turtle";
pub const NTRIPLES: &str = "application/n-triples";
pub const HTML: &str = "text/html";
// Declared alongside the other negotiation-table constants for completeness;
// not yet referenced by `negotiate()` (stored resources are labelled with
// this literal directly in a few places in lib.rs instead). Exercised by
// this module's own unit tests.
#[cfg_attr(not(test), allow(dead_code))]
pub const OCTET_STREAM: &str = "application/octet-stream";

/// Parsed Accept header entry with quality value.
#[derive(Debug, Clone)]
pub struct AcceptEntry {
    pub media_type: String,
    pub quality: f32,
}

/// Parse an Accept header into sorted entries (highest quality first).
pub fn parse_accept(header: &str) -> Vec<AcceptEntry> {
    let mut entries: Vec<AcceptEntry> = header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            let mut media_type = part;
            let mut quality = 1.0f32;

            if let Some(q_pos) = part.find(";q=") {
                media_type = &part[..q_pos];
                if let Ok(q) = part[q_pos + 3..].trim().parse::<f32>() {
                    quality = q.clamp(0.0, 1.0);
                }
            } else if let Some(semi) = part.find(';') {
                media_type = &part[..semi];
            }

            Some(AcceptEntry {
                media_type: media_type.trim().to_lowercase(),
                quality,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        b.quality
            .partial_cmp(&a.quality)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    entries
}

/// Outcome of content negotiation for a resource GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    /// Serve the resource using this content type.
    ContentType(String),
    /// No representation acceptable to the client can be produced — the
    /// caller should respond `406 Not Acceptable`.
    NotAcceptable,
}

/// Negotiate the best content type based on Accept header and resource type.
///
/// This crate has no RDF serializer dependency (no `oxigraph`/`sophia`/etc.),
/// so a JSON-LD-stored resource cannot actually be re-encoded as Turtle.
/// Previously an explicit `Accept: text/turtle` request against an RDF
/// resource silently got JSON-LD back, which breaks Turtle-only Solid/LDP
/// clients that can't parse JSON-LD and violates HTTP content negotiation
/// (RFC 9110 §12.5.1 — a server must not return a representation the client
/// didn't indicate it can accept). We now honour Turtle when it's genuinely
/// acceptable (see below) and otherwise return [`Negotiated::NotAcceptable`]
/// rather than substituting JSON-LD. JSON-LD stays the default whenever the
/// client sends no `Accept` header, sends `*/*`, or explicitly accepts
/// `application/ld+json`/`application/json` (at any position in the list).
pub fn negotiate(accept_header: Option<&str>, stored_content_type: &str) -> Negotiated {
    let accept = match accept_header {
        Some(h) => parse_accept(h),
        None => return Negotiated::ContentType(stored_content_type.to_string()),
    };
    if accept.is_empty() {
        return Negotiated::ContentType(stored_content_type.to_string());
    }

    // Set once we see an `Accept: text/turtle` entry against an RDF resource
    // we cannot actually serve as Turtle. We keep scanning the rest of the
    // (quality-sorted) list in case a later, still-acceptable entry (e.g.
    // `application/ld+json` or `*/*`) resolves the request anyway.
    let mut turtle_requested_but_unservable = false;

    // Check what the client wants in order of preference
    for entry in &accept {
        match entry.media_type.as_str() {
            "*/*" => return Negotiated::ContentType(stored_content_type.to_string()),
            t if t == stored_content_type => {
                return Negotiated::ContentType(stored_content_type.to_string())
            }
            JSONLD | JSON => {
                // If stored as JSON-LD, serve directly
                if stored_content_type == JSONLD || stored_content_type == JSON {
                    return Negotiated::ContentType(JSONLD.to_string());
                }
            }
            TURTLE => {
                // We have no Turtle serializer, so a Turtle representation of
                // an RDF resource can never actually be produced. Record that
                // and fall through (don't relabel JSON-LD as Turtle).
                if is_rdf_type(stored_content_type) {
                    turtle_requested_but_unservable = true;
                }
            }
            HTML => {
                // Only honor an explicit `text/html` request when the resource
                // is actually stored as HTML. Otherwise a stored .json/.txt/.svg
                // could be relabeled `text/html` purely via the Accept header and
                // rendered as active content by the browser — a stored-XSS /
                // content-type-confusion vector on the (often shared) pod origin.
                // Fall through to the stored type instead of forcing HTML.
                if stored_content_type == HTML {
                    return Negotiated::ContentType(HTML.to_string());
                }
            }
            _ => continue,
        }
    }

    if turtle_requested_but_unservable {
        return Negotiated::NotAcceptable;
    }

    // Default: serve as stored
    Negotiated::ContentType(stored_content_type.to_string())
}

/// Check if a content type is an RDF format.
pub fn is_rdf_type(content_type: &str) -> bool {
    matches!(content_type, JSONLD | JSON | TURTLE | NTRIPLES)
}

/// JSON-LD context compaction: ensure a document has the standard Solid context.
///
/// Not yet called from any production write path in this crate (resource PUT
/// handling stores caller-supplied JSON-LD as-is) — kept for callers that
/// need to backfill a `@context` before serving a synthesized document, and
/// exercised directly by this module's unit tests.
#[cfg_attr(not(test), allow(dead_code))]
pub fn ensure_solid_context(doc: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = doc {
        if !map.contains_key("@context") {
            map.insert(
                "@context".to_string(),
                serde_json::json!({
                    "ldp": "http://www.w3.org/ns/ldp#",
                    "dcterms": "http://purl.org/dc/terms/",
                    "foaf": "http://xmlns.com/foaf/0.1/",
                    "solid": "http://www.w3.org/ns/solid/terms#",
                    "schema": "http://schema.org/",
                    "acl": "http://www.w3.org/ns/auth/acl#"
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_accept() {
        let entries = parse_accept("application/ld+json, text/turtle");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].media_type, JSONLD);
        assert_eq!(entries[0].quality, 1.0);
    }

    #[test]
    fn parse_accept_with_quality() {
        let entries = parse_accept("text/turtle;q=0.9, application/ld+json;q=1.0");
        assert_eq!(entries[0].media_type, JSONLD);
        assert_eq!(entries[1].media_type, TURTLE);
    }

    #[test]
    fn parse_accept_wildcard() {
        let entries = parse_accept("*/*");
        assert_eq!(entries[0].media_type, "*/*");
    }

    #[test]
    fn parse_accept_empty_parts_skipped() {
        let entries = parse_accept("application/ld+json, , text/turtle");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_accept_quality_clamped() {
        let entries = parse_accept("text/turtle;q=1.5");
        assert_eq!(entries[0].quality, 1.0);
        let entries = parse_accept("text/turtle;q=-0.5");
        assert_eq!(entries[0].quality, 0.0);
    }

    #[test]
    fn parse_accept_semicolon_without_q() {
        let entries = parse_accept("text/turtle;charset=utf-8");
        assert_eq!(entries[0].media_type, TURTLE);
        assert_eq!(entries[0].quality, 1.0);
    }

    #[test]
    fn negotiate_jsonld_preferred() {
        let result = negotiate(Some("application/ld+json"), JSONLD);
        assert_eq!(result, Negotiated::ContentType(JSONLD.to_string()));
    }

    #[test]
    fn negotiate_no_accept_returns_stored() {
        let result = negotiate(None, "image/png");
        assert_eq!(result, Negotiated::ContentType("image/png".to_string()));
    }

    #[test]
    fn negotiate_wildcard_returns_stored() {
        let result = negotiate(Some("*/*"), "image/jpeg");
        assert_eq!(result, Negotiated::ContentType("image/jpeg".to_string()));
    }

    #[test]
    fn negotiate_json_returns_jsonld() {
        let result = negotiate(Some("application/json"), JSONLD);
        assert_eq!(result, Negotiated::ContentType(JSONLD.to_string()));
    }

    #[test]
    fn negotiate_turtle_only_against_rdf_is_not_acceptable() {
        // No Turtle serializer exists in this crate, so a Turtle-only Accept
        // header against a JSON-LD-stored RDF resource must 406 rather than
        // silently substitute JSON-LD (the previous, buggy behaviour).
        let result = negotiate(Some("text/turtle"), JSONLD);
        assert_eq!(result, Negotiated::NotAcceptable);
    }

    #[test]
    fn negotiate_turtle_with_jsonld_fallback_serves_jsonld() {
        // Turtle is preferred but JSON-LD is also explicitly acceptable, so
        // the request IS satisfiable — serve JSON-LD, no 406.
        let result = negotiate(Some("text/turtle;q=0.9, application/ld+json;q=1.0"), JSONLD);
        assert_eq!(result, Negotiated::ContentType(JSONLD.to_string()));
    }

    #[test]
    fn negotiate_turtle_with_wildcard_fallback_serves_stored() {
        let result = negotiate(Some("text/turtle, */*;q=0.1"), JSONLD);
        assert_eq!(result, Negotiated::ContentType(JSONLD.to_string()));
    }

    #[test]
    fn negotiate_turtle_against_non_rdf_serves_stored() {
        // Turtle requested against a non-RDF resource (e.g. an image) is not
        // an RDF-conversion problem at all — fall back to the stored type.
        let result = negotiate(Some("text/turtle"), "image/png");
        assert_eq!(result, Negotiated::ContentType("image/png".to_string()));
    }

    #[test]
    fn negotiate_html_request_does_not_relabel_nonhtml_stored() {
        // Security: a stored JSON-LD resource must NOT be served as text/html
        // just because the client sent `Accept: text/html` (content-type
        // confusion / stored-XSS guard). It must fall back to the stored type.
        let result = negotiate(Some("text/html"), JSONLD);
        assert_eq!(result, Negotiated::ContentType(JSONLD.to_string()));
    }

    #[test]
    fn negotiate_html_only_when_stored_is_html() {
        // text/html is honored only when the resource is genuinely stored as HTML.
        let result = negotiate(Some("text/html"), HTML);
        assert_eq!(result, Negotiated::ContentType(HTML.to_string()));
    }

    #[test]
    fn negotiate_html_request_on_image_returns_stored() {
        let result = negotiate(Some("text/html"), "image/svg+xml");
        assert_eq!(result, Negotiated::ContentType("image/svg+xml".to_string()));
    }

    #[test]
    fn negotiate_unknown_returns_stored() {
        let result = negotiate(Some("application/xml"), "image/png");
        assert_eq!(result, Negotiated::ContentType("image/png".to_string()));
    }

    #[test]
    fn is_rdf_recognizes_types() {
        assert!(is_rdf_type(JSONLD));
        assert!(is_rdf_type(JSON));
        assert!(is_rdf_type(TURTLE));
        assert!(is_rdf_type(NTRIPLES));
        assert!(!is_rdf_type("image/png"));
        assert!(!is_rdf_type("text/html"));
        assert!(!is_rdf_type(OCTET_STREAM));
    }

    #[test]
    fn ensure_context_adds_when_missing() {
        let mut doc = serde_json::json!({"name": "test"});
        ensure_solid_context(&mut doc);
        assert!(doc.get("@context").is_some());
        let ctx = doc.get("@context").unwrap();
        assert!(ctx.get("ldp").is_some());
        assert!(ctx.get("solid").is_some());
        assert!(ctx.get("foaf").is_some());
        assert!(ctx.get("acl").is_some());
    }

    #[test]
    fn ensure_context_preserves_existing() {
        let mut doc = serde_json::json!({"@context": "http://example.org", "name": "test"});
        ensure_solid_context(&mut doc);
        assert_eq!(doc["@context"], "http://example.org");
    }

    #[test]
    fn ensure_context_noop_for_non_object() {
        let mut doc = serde_json::json!([1, 2, 3]);
        ensure_solid_context(&mut doc);
        assert!(doc.is_array());
    }
}
