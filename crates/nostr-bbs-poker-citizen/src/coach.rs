//! The practice table's coach, the pure half: recognising a request from the
//! table, shaping the question for an OpenAI-compatible chat endpoint, and
//! shaping the reply the table shows. The binary `nostr-bbs-poker-coach`
//! joins this to the forum relay and to the model.
//!
//! The table ([`REQUEST_TAG`] in the forum client's `poker::coach`) DMs the
//! coach one decision at a time, as an ordinary kind-14 rumor in a gift
//! wrap. The reply is the same transport back, starting with [`REPLY_TAG`]
//! so the member's inbox leaves the exchange to the table. Nothing in the
//! request names the opponent's cards; the coach only ever sees what the
//! member sees.

use serde_json::{json, Map, Value};

/// The first line of every request the table sends.
pub const REQUEST_TAG: &str = "[poker-coach]";
/// What every reply starts with.
pub const REPLY_TAG: &str = "[coach]";
/// The most characters a reply carries after the tag: the box under the
/// table is small, and a model that runs on is cut here.
pub const MAX_REPLY_CHARS: usize = 1_500;

/// What the coach is told it is, unless a deployment supplies its own.
pub const DEFAULT_SYSTEM_PROMPT: &str = "You are the coach beside a beginner at a heads-up \
fixed-limit Texas hold'em practice table. Every message gives you the exact decision they face: \
the stakes, both stacks, who has the button, their two cards, the board so far, the betting so \
far, and the legal actions with their prices. Reply in at most 90 words as three numbered \
lines: 1) the one legal action to take, named exactly as it was offered; 2) why, in one plain \
sentence; 3) one short tip a beginner can carry to the next hand. Never invent cards or actions \
that were not given, never guess at the opponent's hidden cards, and write nothing after line 3.";

/// What the table is sent when the model did not answer in time or at all,
/// so the box says something rather than waiting out its timeout.
pub const FALLBACK_REPLY: &str =
    "[coach]\nI could not think this one through in time. Play on, and ask again next turn.";

/// Whether a DM's text is a request from the table.
pub fn is_request(content: &str) -> bool {
    content.trim_start().starts_with(REQUEST_TAG)
}

/// The body of a chat-completions request: the system prompt, the member's
/// request as the user turn, and a deployment's extra fields (a model's
/// thinking switch, a façade's options) merged in last, so they win.
pub fn chat_request(
    model: &str,
    system: &str,
    user: &str,
    max_tokens: u32,
    extra: Option<&Value>,
) -> Value {
    let mut body = Map::new();
    body.insert("model".into(), json!(model));
    body.insert("max_tokens".into(), json!(max_tokens));
    body.insert("temperature".into(), json!(0.4));
    body.insert(
        "messages".into(),
        json!([
            { "role": "system", "content": system },
            { "role": "user", "content": user.trim() },
        ]),
    );
    if let Some(Value::Object(fields)) = extra {
        for (k, v) in fields {
            body.insert(k.clone(), v.clone());
        }
    }
    Value::Object(body)
}

/// The answer in a chat-completions response: the first choice's message
/// content, with any thinking block and a tag the model echoed taken off.
/// `None` when the body is not such a response or the answer is empty.
pub fn answer_from(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let content = v
        .get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()?;
    let after_thinking = match content.rfind("</think>") {
        Some(i) => &content[i + "</think>".len()..],
        None => content,
    };
    let t = after_thinking.trim();
    let t = t
        .strip_prefix(REPLY_TAG)
        .map(|rest| rest.trim_start_matches([':', '-', ' ', '\n']))
        .unwrap_or(t)
        .trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// The text of a reply: the tag, a line break, and the answer cut at
/// [`MAX_REPLY_CHARS`] on a character boundary.
pub fn reply_content(answer: &str) -> String {
    let body: String = answer.trim().chars().take(MAX_REPLY_CHARS).collect();
    format!("{REPLY_TAG}\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_known_by_its_tag() {
        assert!(is_request("[poker-coach]\nI am a beginner"));
        assert!(is_request("  [poker-coach] x"));
        assert!(!is_request("[coach]\nFold"));
        assert!(!is_request("hello coach"));
    }

    #[test]
    fn the_request_carries_both_turns_and_the_extras_win() {
        let extra =
            json!({ "temperature": 0.1, "chat_template_kwargs": { "enable_thinking": false } });
        let body = chat_request("m", "sys", "  [poker-coach]\nq  ", 300, Some(&extra));
        assert_eq!(body["model"], "m");
        assert_eq!(body["max_tokens"], 300);
        assert_eq!(body["temperature"], 0.1);
        assert_eq!(body["chat_template_kwargs"]["enable_thinking"], false);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "sys");
        assert_eq!(body["messages"][1]["content"], "[poker-coach]\nq");
    }

    #[test]
    fn a_non_object_extra_is_ignored() {
        let body = chat_request("m", "s", "u", 10, Some(&json!([1, 2])));
        assert!(body.get("0").is_none());
        assert_eq!(body["messages"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn the_answer_is_the_first_choice_without_thinking_or_tag() {
        let body = json!({ "choices": [{ "message": {
            "content": "<think>hmm\nlots</think>\n[coach]\n1) Fold\n2) Weak.\n3) Tip." } }] });
        assert_eq!(
            answer_from(&body.to_string()).as_deref(),
            Some("1) Fold\n2) Weak.\n3) Tip.")
        );
        let echoed =
            json!({ "choices": [{ "message": { "content": "[coach]: 1) fold\n2) Weak." } }] });
        assert_eq!(
            answer_from(&echoed.to_string()).as_deref(),
            Some("1) fold\n2) Weak.")
        );
    }

    #[test]
    fn an_empty_or_malformed_answer_is_none() {
        assert_eq!(answer_from("not json"), None);
        assert_eq!(answer_from(r#"{"choices":[]}"#), None);
        let empty = json!({ "choices": [{ "message": { "content": "  [coach]  " } }] });
        assert_eq!(answer_from(&empty.to_string()), None);
    }

    #[test]
    fn the_reply_is_tagged_and_capped() {
        assert_eq!(reply_content("  1) Fold  "), "[coach]\n1) Fold");
        let long = "é".repeat(MAX_REPLY_CHARS + 10);
        let r = reply_content(&long);
        assert!(r.starts_with("[coach]\n"));
        assert_eq!(r.chars().count(), "[coach]\n".len() + MAX_REPLY_CHARS);
        assert!(FALLBACK_REPLY.starts_with(REPLY_TAG));
    }
}
