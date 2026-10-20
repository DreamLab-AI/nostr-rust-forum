//! The rumors a NIP-17 DM can carry beyond plain chat (ADR-2027 decision 1).
//!
//! Building (outgoing) and reading (incoming) are both pure, so the tag shapes
//! are asserted on the host target. The envelope — seal and wrap — is core's
//! `gift_wrap_rumor_*_with_signer`; nothing here touches keys.
//!
//! Kinds: 14 chat (optionally a reply and/or carrying `imeta`), 7 reaction,
//! 5 deletion, 15 file message (receive only).

use nostr_bbs_core::gift_wrap::create_rumor_kind;
use nostr_bbs_core::UnsignedEvent;

/// NIP-17 chat message.
pub const KIND_CHAT: u64 = 14;
/// NIP-25 reaction.
pub const KIND_REACTION: u64 = 7;
/// NIP-09 deletion request.
pub const KIND_DELETION: u64 = 5;

/// Longest reaction we will keep (an emoji sequence or `+` / `-`).
const MAX_REACTION_CHARS: usize = 16;
/// Longest attachment URL we will keep.
const MAX_URL_BYTES: usize = 2048;
/// `imeta` tags added to one outgoing message, at most.
const MAX_IMETA: usize = 8;
/// MIME type assumed when a file message names none, or names nonsense.
const FALLBACK_MIME: &str = "application/octet-stream";

/// A file message's attachment. The URL is only ever rendered as a link the
/// reader chooses to open: nothing here fetches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// `https:` URL of the file.
    pub url: String,
    /// MIME type from the rumor's `file-type` tag (sanitised).
    pub file_type: String,
}

/// A rumor read from an incoming wrap, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A chat message (kind 14). The existing path handles it.
    Chat,
    /// A reaction (kind 7) to the message whose rumor id is `target`.
    Reaction {
        /// Rumor id of the message reacted to.
        target: String,
        /// The reaction content (`+`, `-` or an emoji).
        emoji: String,
    },
    /// A deletion request (kind 5) for the rumors in `targets`.
    Deletion {
        /// Rumor ids the sender asks to delete.
        targets: Vec<String>,
    },
    /// A file message (kind 15).
    File(Attachment),
}

pub fn is_rumor_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The `e` tag values of a rumor that are well-formed ids, lowercased.
fn e_targets(rumor: &UnsignedEvent) -> Vec<String> {
    rumor
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "e" && is_rumor_id(&t[1]))
        .map(|t| t[1].to_ascii_lowercase())
        .collect()
}

/// A `https:` URL with nothing in it a browser would treat specially.
///
/// Anything else, `javascript:` and `data:` included, is refused: a file
/// message's URL becomes an `href`.
pub fn safe_https_url(s: &str) -> Option<&str> {
    let ok = s.len() <= MAX_URL_BYTES
        && s.starts_with("https://")
        && s.len() > "https://".len()
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        && !s.contains(['<', '>', '"', '\'', '\\']);
    ok.then_some(s)
}

/// A MIME type that is only `type/subtype` token characters, lowercased.
fn sanitise_mime(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let token = |p: &str| {
        !p.is_empty()
            && p.len() <= 64
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    };
    let (ty, sub) = s.split_once('/')?;
    (token(ty) && token(sub)).then_some(s)
}

/// Classify an unwrapped rumor, or `None` when it is malformed or not a kind
/// this screen understands. Chat is reported as [`Incoming::Chat`] and left to
/// the existing path.
pub fn classify(rumor: &UnsignedEvent) -> Option<Incoming> {
    match rumor.kind {
        KIND_CHAT => Some(Incoming::Chat),
        KIND_REACTION => {
            // NIP-25: the target is the LAST `e` tag.
            let target = e_targets(rumor).pop()?;
            let emoji = match rumor.content.trim() {
                "" => "+".to_string(),
                c if c.chars().count() <= MAX_REACTION_CHARS => c.to_string(),
                _ => return None,
            };
            Some(Incoming::Reaction { target, emoji })
        }
        KIND_DELETION => {
            let targets = e_targets(rumor);
            (!targets.is_empty()).then_some(Incoming::Deletion { targets })
        }
        15 => {
            let url = safe_https_url(rumor.content.trim())?.to_string();
            let file_type = rumor
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "file-type")
                .and_then(|t| sanitise_mime(&t[1]))
                .unwrap_or_else(|| FALLBACK_MIME.to_string());
            Some(Incoming::File(Attachment { url, file_type }))
        }
        _ => None,
    }
}

/// MIME type for a media URL by file extension, if it is a media type we tag.
fn media_mime(url: &str) -> Option<&'static str> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let ext = path.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        _ => return None,
    })
}

/// NIP-92 `imeta` tags for each distinct `https:` media URL in `content`.
fn imeta_tags(content: &str) -> Vec<Vec<String>> {
    let mut seen: Vec<&str> = Vec::new();
    let mut tags = Vec::new();
    for word in content.split_whitespace() {
        let word = word.trim_end_matches(['.', ',', ')', ';', '!']);
        let (Some(url), true) = (safe_https_url(word), seen.len() < MAX_IMETA) else {
            continue;
        };
        let Some(mime) = media_mime(url) else {
            continue;
        };
        if seen.contains(&url) {
            continue;
        }
        seen.push(url);
        tags.push(vec![
            "imeta".to_string(),
            format!("url {url}"),
            format!("m {mime}"),
        ]);
    }
    tags
}

/// A kind 14 chat rumor to `recipient`: the `p` tag, an
/// `["e", reply_to, "", "reply"]` tag when it answers a message, and `imeta`
/// for any media URL in the text.
pub fn chat_rumor(
    me: &str,
    recipient: &str,
    content: &str,
    reply_to: Option<&str>,
) -> UnsignedEvent {
    let mut rumor = create_rumor_kind(me, recipient, KIND_CHAT, content);
    if let Some(id) = reply_to.filter(|id| is_rumor_id(id)) {
        rumor.tags.push(vec![
            "e".to_string(),
            id.to_ascii_lowercase(),
            String::new(),
            "reply".to_string(),
        ]);
    }
    rumor.tags.extend(imeta_tags(content));
    rumor
}

/// A kind 7 reaction to the message whose rumor id is `target`. Addressed to
/// the conversation partner, so both copies file under the same thread.
pub fn reaction_rumor(me: &str, recipient: &str, target: &str, emoji: &str) -> UnsignedEvent {
    let mut rumor = create_rumor_kind(me, recipient, KIND_REACTION, emoji);
    rumor.tags.push(vec!["e".to_string(), target.to_string()]);
    rumor
        .tags
        .push(vec!["k".to_string(), KIND_CHAT.to_string()]);
    rumor
}

/// A kind 5 deletion request for the rumors in `targets` (our own messages).
pub fn deletion_rumor(me: &str, recipient: &str, targets: &[String]) -> UnsignedEvent {
    let mut rumor = create_rumor_kind(me, recipient, KIND_DELETION, "");
    for id in targets {
        rumor.tags.push(vec!["e".to_string(), id.clone()]);
    }
    rumor
        .tags
        .push(vec!["k".to_string(), KIND_CHAT.to_string()]);
    rumor
}

/// Fixed refusal for an outgoing rumor tagging someone other than the pair.
pub const ERR_BAD_PTAG: &str = "That message could not be sent (invalid recipient tag)";
/// Fixed refusal for an outgoing rumor pointing at a message we do not hold.
pub const ERR_UNKNOWN_REF: &str = "That message could not be sent (unknown message reference)";

/// Check a caller-built rumor before it is wrapped.
///
/// * Every `p` tag must name `recipient` or `me`; a rumor that tags a third
///   party would be a lie about who the conversation is with.
/// * Every `e` tag (a reaction's target, a deletion's targets, a reply's parent)
///   must satisfy `known`: a message already in this conversation's local store.
///
/// Refuses with a fixed message and says nothing about which tag offended.
pub fn validate_outgoing(
    rumor: &UnsignedEvent,
    recipient: &str,
    me: &str,
    known: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    for tag in &rumor.tags {
        match tag.first().map(String::as_str) {
            Some("p") => {
                let ok = tag
                    .get(1)
                    .is_some_and(|v| v.as_str() == recipient || v.as_str() == me);
                if !ok {
                    return Err(ERR_BAD_PTAG.to_string());
                }
            }
            Some("e") => {
                let ok = tag.get(1).is_some_and(|v| is_rumor_id(v) && known(v));
                if !ok {
                    return Err(ERR_UNKNOWN_REF.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "a41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a";
    const YOU: &str = "b41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a";
    const TARGET: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

    fn rumor(kind: u64, tags: Vec<Vec<&str>>, content: &str) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: YOU.into(),
            created_at: 1,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: content.into(),
        }
    }

    #[test]
    fn a_reaction_points_at_its_e_tag_and_defaults_to_plus() {
        let r = rumor(7, vec![vec!["p", ME], vec!["e", TARGET]], "");
        assert_eq!(
            classify(&r),
            Some(Incoming::Reaction {
                target: TARGET.into(),
                emoji: "+".into()
            })
        );
        let r = rumor(7, vec![vec!["e", TARGET]], "🔥");
        assert!(matches!(classify(&r), Some(Incoming::Reaction { emoji, .. }) if emoji == "🔥"));
    }

    #[test]
    fn a_reaction_without_a_valid_target_or_with_a_overlong_content_is_dropped() {
        assert_eq!(classify(&rumor(7, vec![vec!["p", ME]], "+")), None);
        assert_eq!(classify(&rumor(7, vec![vec!["e", "short"]], "+")), None);
        let long = "x".repeat(40);
        assert_eq!(classify(&rumor(7, vec![vec!["e", TARGET]], &long)), None);
    }

    #[test]
    fn a_deletion_lists_every_valid_e_target() {
        let r = rumor(
            5,
            vec![vec!["e", TARGET], vec!["e", "bogus"], vec!["k", "14"]],
            "",
        );
        assert_eq!(
            classify(&r),
            Some(Incoming::Deletion {
                targets: vec![TARGET.into()]
            })
        );
        assert_eq!(classify(&rumor(5, vec![vec!["k", "14"]], "")), None);
    }

    #[test]
    fn a_file_message_keeps_its_url_and_honours_file_type() {
        let r = rumor(
            15,
            vec![vec!["file-type", "Image/PNG"]],
            "https://files.example.com/a.png",
        );
        assert_eq!(
            classify(&r),
            Some(Incoming::File(Attachment {
                url: "https://files.example.com/a.png".into(),
                file_type: "image/png".into()
            }))
        );
    }

    #[test]
    fn a_file_message_without_a_usable_type_falls_back_to_octet_stream() {
        let r = rumor(
            15,
            vec![vec!["file-type", "text/html; <script>"]],
            "https://f.example.com/x",
        );
        assert!(matches!(classify(&r),
            Some(Incoming::File(a)) if a.file_type == "application/octet-stream"));
    }

    #[test]
    fn only_https_urls_become_attachments() {
        for bad in [
            "javascript:alert(1)",
            "http://plain.example.com/a.png",
            "data:text/html;base64,AAAA",
            "https://x.example.com/a b",
            "https://x.example.com/\"onload=",
            "",
        ] {
            assert_eq!(classify(&rumor(15, vec![], bad)), None, "{bad}");
        }
    }

    #[test]
    fn other_kinds_are_not_ours_and_chat_is_left_to_the_existing_path() {
        assert_eq!(classify(&rumor(1, vec![], "x")), None);
        assert_eq!(classify(&rumor(14, vec![], "hi")), Some(Incoming::Chat));
    }

    #[test]
    fn a_reply_carries_the_e_tag_with_the_reply_marker() {
        let r = chat_rumor(ME, YOU, "agreed", Some(TARGET));
        assert!(r.tags.contains(&vec![
            "e".into(),
            TARGET.into(),
            String::new(),
            "reply".into()
        ]));
        assert!(r.tags.contains(&vec!["p".into(), YOU.into()]));
        assert_eq!(r.kind, 14);
    }

    #[test]
    fn a_reply_to_something_that_is_not_an_id_adds_no_tag() {
        let r = chat_rumor(ME, YOU, "hi", Some("local-123-4-deadbeef"));
        assert!(r.tags.iter().all(|t| t[0] != "e"));
    }

    #[test]
    fn media_urls_get_imeta_and_plain_text_does_not() {
        let r = chat_rumor(
            ME,
            YOU,
            "look https://m.example.com/a.JPG?x=1, and https://m.example.com/a.JPG?x=1 \
             also http://insecure.example.com/b.png and https://m.example.com/page",
            None,
        );
        let imeta: Vec<_> = r.tags.iter().filter(|t| t[0] == "imeta").collect();
        assert_eq!(imeta.len(), 1);
        assert_eq!(imeta[0][1], "url https://m.example.com/a.JPG?x=1");
        assert_eq!(imeta[0][2], "m image/jpeg");
        assert!(chat_rumor(ME, YOU, "no media", None)
            .tags
            .iter()
            .all(|t| t[0] != "imeta"));
    }

    #[test]
    fn reaction_and_deletion_rumors_have_the_nip_shapes() {
        let r = reaction_rumor(ME, YOU, TARGET, "+");
        assert_eq!((r.kind, r.content.as_str()), (7, "+"));
        assert!(r.tags.contains(&vec!["e".into(), TARGET.into()]));
        assert!(r.tags.contains(&vec!["p".into(), YOU.into()]));
        assert_eq!(
            classify(&r),
            Some(Incoming::Reaction {
                target: TARGET.into(),
                emoji: "+".into()
            })
        );

        let d = deletion_rumor(ME, YOU, &[TARGET.to_string()]);
        assert_eq!((d.kind, d.content.as_str()), (5, ""));
        assert_eq!(
            classify(&d),
            Some(Incoming::Deletion {
                targets: vec![TARGET.into()]
            })
        );
    }

    #[test]
    fn outgoing_p_tags_must_be_the_pair() {
        let ok = chat_rumor(ME, YOU, "hi", None);
        assert!(validate_outgoing(&ok, YOU, ME, &|_| true).is_ok());
        let mut bad = ok.clone();
        bad.tags.push(vec!["p".into(), "e".repeat(64)]);
        assert_eq!(
            validate_outgoing(&bad, YOU, ME, &|_| true),
            Err(ERR_BAD_PTAG.to_string())
        );
        let mut empty = ok;
        empty.tags.push(vec!["p".into()]);
        assert!(validate_outgoing(&empty, YOU, ME, &|_| true).is_err());
    }

    #[test]
    fn outgoing_e_tags_must_be_known_messages() {
        let known = |id: &str| id == TARGET;
        let reply = chat_rumor(ME, YOU, "re", Some(TARGET));
        assert!(validate_outgoing(&reply, YOU, ME, &known).is_ok());
        for r in [
            reaction_rumor(ME, YOU, &"f".repeat(64), "+"),
            deletion_rumor(ME, YOU, &["f".repeat(64)]),
            chat_rumor(ME, YOU, "re", Some(&"f".repeat(64))),
        ] {
            let outcome = validate_outgoing(&r, YOU, ME, &known);
            // A reply to an unknown id never gets its `e` tag at all (the
            // builder drops non-ids only); either way no unknown id is sent.
            if r.tags.iter().any(|t| t[0] == "e") {
                assert_eq!(outcome, Err(ERR_UNKNOWN_REF.to_string()));
            }
        }
        assert!(validate_outgoing(&reaction_rumor(ME, YOU, TARGET, "+"), YOU, ME, &known).is_ok());
        assert!(
            validate_outgoing(&deletion_rumor(ME, YOU, &[TARGET.into()]), YOU, ME, &known).is_ok()
        );
    }
}
