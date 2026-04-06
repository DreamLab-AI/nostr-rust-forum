//! JSON Patch (RFC 6902) support for pod resources.
//!
//! Supports add, remove, replace operations on JSON-LD documents.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    pub path: String,
    pub value: Option<serde_json::Value>,
}

/// Apply a set of JSON Patch operations to a JSON document.
pub fn apply_patches(
    document: &mut serde_json::Value,
    operations: &[PatchOperation],
) -> Result<(), String> {
    for op in operations {
        match op.op.as_str() {
            "add" => {
                let value = op
                    .value
                    .as_ref()
                    .ok_or_else(|| "add operation requires value".to_string())?;
                json_pointer_set(document, &op.path, value.clone())?;
            }
            "remove" => {
                json_pointer_remove(document, &op.path)?;
            }
            "replace" => {
                let value = op
                    .value
                    .as_ref()
                    .ok_or_else(|| "replace operation requires value".to_string())?;
                // Verify the target exists before replacing
                json_pointer_remove(document, &op.path)?;
                json_pointer_set(document, &op.path, value.clone())?;
            }
            other => return Err(format!("unsupported operation: {other}")),
        }
    }
    Ok(())
}

fn json_pointer_set(
    doc: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    if path.is_empty() || path == "/" {
        *doc = value;
        return Ok(());
    }

    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let mut current = doc;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last segment -- set the value
            match current {
                serde_json::Value::Object(map) => {
                    map.insert(part.to_string(), value);
                    return Ok(());
                }
                serde_json::Value::Array(arr) => {
                    if *part == "-" {
                        arr.push(value);
                        return Ok(());
                    }
                    let idx: usize = part
                        .parse()
                        .map_err(|_| format!("invalid array index: {part}"))?;
                    if idx <= arr.len() {
                        arr.insert(idx, value);
                        return Ok(());
                    }
                    return Err(format!("array index out of bounds: {idx}"));
                }
                _ => return Err(format!("cannot set property on non-object/array at {path}")),
            }
        }
        // Navigate deeper
        current = match current {
            serde_json::Value::Object(map) => map
                .entry(part.to_string())
                .or_insert(serde_json::Value::Object(Default::default())),
            serde_json::Value::Array(arr) => {
                let idx: usize = part
                    .parse()
                    .map_err(|_| format!("invalid array index: {part}"))?;
                arr.get_mut(idx)
                    .ok_or_else(|| format!("array index out of bounds: {idx}"))?
            }
            _ => {
                return Err(format!(
                    "cannot navigate into non-object/array at segment {part}"
                ))
            }
        };
    }

    Err("empty path".into())
}

fn json_pointer_remove(doc: &mut serde_json::Value, path: &str) -> Result<(), String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() {
        return Err("cannot remove root".into());
    }

    let mut current = doc;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            match current {
                serde_json::Value::Object(map) => {
                    map.remove(*part);
                    return Ok(());
                }
                serde_json::Value::Array(arr) => {
                    let idx: usize = part
                        .parse()
                        .map_err(|_| format!("invalid index: {part}"))?;
                    if idx < arr.len() {
                        arr.remove(idx);
                        return Ok(());
                    }
                    return Err(format!("index out of bounds: {idx}"));
                }
                _ => return Err("not an object or array".into()),
            }
        }
        current = match current {
            serde_json::Value::Object(map) => {
                map.get_mut(*part).ok_or_else(|| format!("key not found: {part}"))?
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = part
                    .parse()
                    .map_err(|_| format!("invalid index: {part}"))?;
                arr.get_mut(idx)
                    .ok_or_else(|| format!("index out of bounds: {idx}"))?
            }
            _ => return Err("not navigable".into()),
        };
    }
    Err("empty path".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_to_object() {
        let mut doc = json!({"name": "Alice"});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/age".into(),
            value: Some(json!(30)),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["age"], json!(30));
    }

    #[test]
    fn remove_from_object() {
        let mut doc = json!({"name": "Alice", "age": 30});
        let ops = vec![PatchOperation {
            op: "remove".into(),
            path: "/age".into(),
            value: None,
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert!(doc.get("age").is_none());
    }

    #[test]
    fn replace_value() {
        let mut doc = json!({"name": "Alice"});
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: "/name".into(),
            value: Some(json!("Bob")),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["name"], json!("Bob"));
    }

    #[test]
    fn add_to_array() {
        let mut doc = json!({"items": [1, 2, 3]});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/items/-".into(),
            value: Some(json!(4)),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["items"], json!([1, 2, 3, 4]));
    }

    #[test]
    fn nested_add() {
        let mut doc = json!({"user": {"name": "Alice"}});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/user/email".into(),
            value: Some(json!("alice@example.com")),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["user"]["email"], json!("alice@example.com"));
    }

    #[test]
    fn unsupported_op_errors() {
        let mut doc = json!({});
        let ops = vec![PatchOperation {
            op: "move".into(),
            path: "/a".into(),
            value: None,
        }];
        assert!(apply_patches(&mut doc, &ops).is_err());
    }

    #[test]
    fn add_missing_value_errors() {
        let mut doc = json!({});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/a".into(),
            value: None,
        }];
        assert!(apply_patches(&mut doc, &ops).is_err());
    }

    #[test]
    fn replace_missing_value_errors() {
        let mut doc = json!({"a": 1});
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: "/a".into(),
            value: None,
        }];
        assert!(apply_patches(&mut doc, &ops).is_err());
    }

    #[test]
    fn multiple_operations() {
        let mut doc = json!({"name": "Alice", "age": 25});
        let ops = vec![
            PatchOperation {
                op: "replace".into(),
                path: "/age".into(),
                value: Some(json!(30)),
            },
            PatchOperation {
                op: "add".into(),
                path: "/email".into(),
                value: Some(json!("alice@example.com")),
            },
            PatchOperation {
                op: "remove".into(),
                path: "/name".into(),
                value: None,
            },
        ];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["age"], json!(30));
        assert_eq!(doc["email"], json!("alice@example.com"));
        assert!(doc.get("name").is_none());
    }

    #[test]
    fn add_at_array_index() {
        let mut doc = json!({"items": [1, 2, 3]});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/items/1".into(),
            value: Some(json!(99)),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["items"], json!([1, 99, 2, 3]));
    }

    #[test]
    fn remove_from_array() {
        let mut doc = json!({"items": [1, 2, 3]});
        let ops = vec![PatchOperation {
            op: "remove".into(),
            path: "/items/1".into(),
            value: None,
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["items"], json!([1, 3]));
    }

    #[test]
    fn replace_root_document() {
        let mut doc = json!({"old": true});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "".into(),
            value: Some(json!({"new": true})),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc, json!({"new": true}));
    }

    #[test]
    fn deeply_nested_add() {
        let mut doc = json!({"a": {"b": {"c": 1}}});
        let ops = vec![PatchOperation {
            op: "add".into(),
            path: "/a/b/d".into(),
            value: Some(json!(2)),
        }];
        apply_patches(&mut doc, &ops).unwrap();
        assert_eq!(doc["a"]["b"]["d"], json!(2));
        assert_eq!(doc["a"]["b"]["c"], json!(1));
    }
}
