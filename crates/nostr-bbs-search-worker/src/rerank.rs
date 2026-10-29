//! Jev option (NF-07-S1-01): rerank the *already visible* search hits.
//!
//! Runs strictly after `check_model_match` and `visible_top_k`, so a reranker
//! can neither surface a hidden candidate nor retrieve one the index does not
//! hold. It only permutes a capped head of the visible list; the tail keeps its
//! cosine order. On any [`Fallback`] the caller keeps the pre-change list and
//! the response body is byte-identical to the pre-change body.
//!
//! What leaves the Worker when the flag is on: the trimmed query text and up to
//! [`HEAD_CAP`] public snippets (each <= [`SNIPPET_MAX_CHARS`] chars, stored at
//! ingest only for `public: true` entries). Nothing else.

use nostr_bbs_jev::{ask, Answer, Fallback, JevConfig, JevTransport, Question};
use serde_json::json;
use std::collections::HashMap;

/// Version of the question set below; logged by the caller on acceptance.
pub const QUESTION_SET_VERSION: &str = "forum-search-rerank/1";
/// Flag variable (default off).
pub const FLAG: &str = "JEV_SEARCH_RERANK";
/// Number of leading hits that may be reordered.
pub const HEAD_CAP: usize = 10;
/// Max characters of a stored snippet.
pub const SNIPPET_MAX_CHARS: usize = 280;
/// Default per-answer confidence needed to accept a reorder (unfitted; to be
/// fitted on labelled data before any claim of uplift).
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.5;

/// Result of an accepted rerank.
#[derive(Debug, Clone, PartialEq)]
pub struct Reranked {
    /// New order of the head, as indices into the input slice.
    pub order: Vec<usize>,
    /// Jev's view that no candidate answers the query. Annotation only: it
    /// never removes a result.
    pub no_useful_match: bool,
}

/// Truncate a snippet to [`SNIPPET_MAX_CHARS`] on a char boundary.
pub fn clip_snippet(s: &str) -> String {
    s.trim().chars().take(SNIPPET_MAX_CHARS).collect()
}

fn questions(n: usize) -> Vec<(String, Question)> {
    let mut qs: Vec<(String, Question)> = (0..n)
        .map(|i| {
            (
                format!("rel_{i}"),
                Question::Score {
                    instructions: format!(
                        "How well does the text in `candidates.c{i}` answer or address the search \
                         `query`? Judge only that candidate on its own text."
                    ),
                    criteria: vec![
                        "Unrelated to the query".into(),
                        "On the same topic but does not answer it".into(),
                        "Partly answers the query".into(),
                        "Directly answers the query".into(),
                    ],
                },
            )
        })
        .collect();
    qs.push((
        "none".into(),
        Question::Noul {
            instructions: "Taking all of `candidates` together, is it true that none of them \
                           answers or usefully addresses `query`?"
                .into(),
        },
    ));
    qs
}

/// Ask Jev to rerank `hits` (visible `(id, cosine)` pairs in current order).
///
/// Falls back if any head candidate has no stored snippet, if any answer is
/// below `min_confidence`, or if the response is malformed.
pub async fn rerank<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    query: &str,
    hits: &[(String, f32)],
    snippets: &HashMap<String, String>,
    min_confidence: f64,
) -> Result<Reranked, Fallback> {
    let head = hits.len().min(HEAD_CAP);
    if head < 2 {
        // Nothing to reorder; also nothing worth sending.
        return Err(Fallback::LowConfidence);
    }
    let mut cands = serde_json::Map::new();
    for (i, (id, _)) in hits.iter().take(head).enumerate() {
        let s = snippets
            .get(id)
            .filter(|s| !s.is_empty())
            .ok_or(Fallback::Malformed)?;
        cands.insert(format!("c{i}"), json!(s));
    }
    let state = json!({ "query": query, "candidates": cands });
    let owned = questions(head);
    let qs: Vec<(&str, Question)> = owned.iter().map(|(k, q)| (k.as_str(), q.clone())).collect();
    let answers = ask(transport, cfg, &state, &qs).await?;

    let mut scored: Vec<(usize, f64)> = Vec::with_capacity(head);
    for i in 0..head {
        match answers.get(&format!("rel_{i}")) {
            Some(Answer::Score { score, confidence }) => {
                if *confidence < min_confidence {
                    return Err(Fallback::LowConfidence);
                }
                scored.push((i, *score));
            }
            _ => return Err(Fallback::Malformed),
        }
    }
    let no_useful_match = match answers.get("none") {
        Some(Answer::Noul(p)) => *p >= 0.5,
        _ => return Err(Fallback::Malformed),
    };
    // Stable sort: descending score, ties keep cosine order.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let order: Vec<usize> = scored.into_iter().map(|(i, _)| i).collect();
    if !is_permutation(&order, head) {
        return Err(Fallback::Malformed);
    }
    Ok(Reranked {
        order,
        no_useful_match,
    })
}

/// `order` is a permutation of `0..n`.
pub fn is_permutation(order: &[usize], n: usize) -> bool {
    let mut seen = vec![false; n];
    order.len() == n
        && order
            .iter()
            .all(|&i| i < n && !std::mem::replace(&mut seen[i], true))
}

/// Apply an accepted head order; the tail is untouched.
pub fn apply_order<T: Clone>(items: &[T], order: &[usize]) -> Vec<T> {
    let head = order.len().min(items.len());
    let mut out: Vec<T> = order.iter().take(head).map(|&i| items[i].clone()).collect();
    out.extend_from_slice(&items[head..]);
    out
}

/// Apply one ingest entry to the snippet map: a public entry with non-empty
/// text overwrites; anything else (un-publish, edit without text) deletes.
pub fn apply_snippet(
    map: &mut std::collections::HashMap<String, String>,
    id: &str,
    public: bool,
    snippet: Option<&str>,
) {
    match (public, snippet.map(clip_snippet)) {
        (true, Some(sn)) if !sn.is_empty() => {
            map.insert(id.to_string(), sn);
        }
        _ => {
            map.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_jev::testutil::{block_on, Mock};
    use nostr_bbs_jev::TransportError;

    fn cfg() -> JevConfig {
        JevConfig {
            endpoint: "http://e".into(),
            model: "m".into(),
            bearer: None,
            deadline_ms: 10,
        }
    }
    fn hits(n: usize) -> Vec<(String, f32)> {
        (0..n)
            .map(|i| (format!("id{i}"), 1.0 - i as f32 * 0.1))
            .collect()
    }
    fn snips(n: usize) -> HashMap<String, String> {
        (0..n)
            .map(|i| (format!("id{i}"), format!("text {i}")))
            .collect()
    }
    fn reply(scores: &[f64], conf: f64, none: f64) -> String {
        let mut a = serde_json::Map::new();
        for (i, s) in scores.iter().enumerate() {
            a.insert(
                format!("rel_{i}"),
                json!({"type":"score","score":s,"confidence":conf,"legend":{}}),
            );
        }
        a.insert("none".into(), json!({"type":"noul","noul":none}));
        json!({"model":"m","answers":a,"usage":{"input_tokens":1,"output_tokens":1}}).to_string()
    }
    fn run(m: &Mock, n: usize, sn: &HashMap<String, String>) -> Result<Reranked, Fallback> {
        block_on(rerank(m, &cfg(), "q", &hits(n), sn, DEFAULT_MIN_CONFIDENCE))
    }

    #[test]
    fn accept_path_reorders_head_and_keeps_tail() {
        let m = Mock::new(Ok((200, reply(&[0.5, 3.0, 2.0], 0.9, 0.1))));
        let r = run(&m, 3, &snips(3)).unwrap();
        assert_eq!(r.order, vec![1, 2, 0]);
        assert!(!r.no_useful_match);
        let h = hits(14);
        // tail beyond HEAD_CAP is untouched
        let mut ord: Vec<usize> = (0..10).collect();
        ord.reverse();
        let out = apply_order(&h, &ord);
        assert_eq!(out.len(), 14);
        assert_eq!(&out[10..], &h[10..]);
        assert_eq!(out[0], h[9]);
    }

    #[test]
    fn ties_keep_cosine_order() {
        let m = Mock::new(Ok((200, reply(&[2.0, 2.0, 2.0], 0.9, 0.1))));
        assert_eq!(run(&m, 3, &snips(3)).unwrap().order, vec![0, 1, 2]);
    }

    #[test]
    fn no_useful_match_is_annotation_only() {
        let m = Mock::new(Ok((200, reply(&[0.1, 0.2], 0.9, 0.95))));
        let r = run(&m, 2, &snips(2)).unwrap();
        assert!(r.no_useful_match);
        assert_eq!(r.order.len(), 2, "no result is dropped");
    }

    #[test]
    fn wire_shape() {
        let m = Mock::new(Ok((200, reply(&[1.0, 2.0], 0.9, 0.1))));
        run(&m, 2, &snips(2)).unwrap();
        let body: serde_json::Value = serde_json::from_str(&m.requests.borrow()[0].2).unwrap();
        assert_eq!(body["state"]["query"], "q");
        assert_eq!(body["state"]["candidates"]["c1"], "text 1");
        assert_eq!(body["questions"]["rel_0"]["type"], "score");
        assert!(body["questions"]["rel_0"]["criteria"].is_array());
        assert_eq!(body["questions"]["none"]["type"], "noul");
        // only the query and snippets leave: no ids, no scores
        assert!(!body.to_string().contains("id0"));
    }

    #[test]
    fn every_fallback_trigger() {
        let sn = snips(3);
        type Case = (Result<(u16, String), TransportError>, Fallback);
        let cases: Vec<Case> = vec![
            (Err(TransportError::Timeout), Fallback::Timeout),
            (Err(TransportError::Other), Fallback::Transport),
            (Ok((503, "".into())), Fallback::Http(503)),
            (Ok((200, "{".into())), Fallback::Malformed),
            (Ok((200, r#"{"answers":{}}"#.into())), Fallback::Malformed),
            (
                Ok((200, reply(&[1.0, 2.0, 3.0], 0.1, 0.1))),
                Fallback::LowConfidence,
            ),
            (
                Ok((200, reply(&[9.0, 2.0, 3.0], 0.9, 0.1))),
                Fallback::Malformed,
            ), // score out of rubric
        ];
        for (rep, want) in cases {
            assert_eq!(run(&Mock::new(rep), 3, &sn).unwrap_err(), want);
        }
    }

    #[test]
    fn missing_snippet_falls_back_without_a_request() {
        let mut sn = snips(3);
        sn.remove("id1");
        let m = Mock::new(Ok((200, reply(&[1.0, 2.0, 3.0], 0.9, 0.1))));
        assert_eq!(run(&m, 3, &sn).unwrap_err(), Fallback::Malformed);
        assert!(
            m.requests.borrow().is_empty(),
            "nothing leaves when a snippet is missing"
        );
    }

    #[test]
    fn permutation_guard() {
        assert!(is_permutation(&[2, 0, 1], 3));
        assert!(!is_permutation(&[0, 0, 1], 3));
        assert!(!is_permutation(&[0, 1], 3));
        assert!(!is_permutation(&[0, 1, 3], 3));
    }

    #[test]
    fn clip_is_char_safe() {
        let s = "é".repeat(400);
        assert_eq!(clip_snippet(&s).chars().count(), SNIPPET_MAX_CHARS);
    }
}
