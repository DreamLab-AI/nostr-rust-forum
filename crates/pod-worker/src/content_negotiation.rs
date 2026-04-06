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

/// Negotiate the best content type based on Accept header and resource type.
/// Returns the content type to serve.
pub fn negotiate(accept_header: Option<&str>, stored_content_type: &str) -> String {
    let accept = match accept_header {
        Some(h) => parse_accept(h),
        None => return stored_content_type.to_string(),
    };

    // Check what the client wants in order of preference
    for entry in &accept {
        match entry.media_type.as_str() {
            "*/*" => return stored_content_type.to_string(),
            t if t == stored_content_type => return stored_content_type.to_string(),
            JSONLD | JSON => {
                // If stored as JSON-LD, serve directly
                if stored_content_type == JSONLD || stored_content_type == JSON {
                    return JSONLD.to_string();
                }
            }
            TURTLE => {
                // If stored as JSON-LD, we could convert (future: use a converter)
                // For now, return JSON-LD with a Vary header
                if stored_content_type == JSONLD {
                    return JSONLD.to_string(); // TODO: convert to Turtle
                }
            }
            HTML => {
                return HTML.to_string();
            }
            _ => continue,
        }
    }

    // Default: serve as stored
    stored_content_type.to_string()
}

/// Check if a content type is an RDF format.
pub fn is_rdf_type(content_type: &str) -> bool {
    matches!(content_type, JSONLD | JSON | TURTLE | NTRIPLES)
}

/// JSON-LD context compaction: ensure a document has the standard Solid context.
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
        assert_eq!(result, JSONLD);
    }

    #[test]
    fn negotiate_no_accept_returns_stored() {
        let result = negotiate(None, "image/png");
        assert_eq!(result, "image/png");
    }

    #[test]
    fn negotiate_wildcard_returns_stored() {
        let result = negotiate(Some("*/*"), "image/jpeg");
        assert_eq!(result, "image/jpeg");
    }

    #[test]
    fn negotiate_json_returns_jsonld() {
        let result = negotiate(Some("application/json"), JSONLD);
        assert_eq!(result, JSONLD);
    }

    #[test]
    fn negotiate_turtle_falls_back_to_jsonld() {
        let result = negotiate(Some("text/turtle"), JSONLD);
        assert_eq!(result, JSONLD);
    }

    #[test]
    fn negotiate_html_returns_html() {
        let result = negotiate(Some("text/html"), JSONLD);
        assert_eq!(result, HTML);
    }

    #[test]
    fn negotiate_unknown_returns_stored() {
        let result = negotiate(Some("application/xml"), "image/png");
        assert_eq!(result, "image/png");
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
