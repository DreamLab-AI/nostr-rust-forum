//! BERT-uncased WordPiece tokeniser (the bge-small-en-v1.5 `tokenizer.json`
//! behaviour), written out so the browser worker needs no `tokenizers` crate.
//!
//! Steps, as in BERT's `BasicTokenizer` + `WordpieceTokenizer`: clean control
//! characters and normalise whitespace, space out CJK ideographs, lowercase,
//! strip accents (NFD, drop combining marks), split on punctuation, then
//! greedy longest-match WordPiece with `##` continuations. Parity with the
//! reference `tokenizers` crate is tested on a corpus (dev-dependency).

use std::collections::HashMap;
use unicode_general_category::{get_general_category, GeneralCategory as G};
use unicode_normalization::UnicodeNormalization;

/// `[CLS]`, `[SEP]`, `[UNK]`, `[PAD]` ids and the vocabulary.
pub struct WordPiece {
    vocab: HashMap<String, u32>,
    cls: u32,
    sep: u32,
    unk: u32,
    /// Max sequence length including `[CLS]` and `[SEP]`.
    pub max_len: usize,
}

/// Token ids for one text, `[CLS] … [SEP]`, truncated to `max_len`.
pub type Ids = Vec<u32>;

fn is_control(c: char) -> bool {
    if c == '\t' || c == '\n' || c == '\r' {
        return false;
    }
    matches!(
        get_general_category(c),
        G::Control | G::Format | G::Unassigned | G::PrivateUse | G::Surrogate
    )
}

fn is_whitespace(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n' || c == '\r' || get_general_category(c) == G::SpaceSeparator
}

fn is_punct(c: char) -> bool {
    let u = c as u32;
    if (33..=47).contains(&u)
        || (58..=64).contains(&u)
        || (91..=96).contains(&u)
        || (123..=126).contains(&u)
    {
        return true;
    }
    matches!(
        get_general_category(c),
        G::ConnectorPunctuation
            | G::DashPunctuation
            | G::OpenPunctuation
            | G::ClosePunctuation
            | G::InitialPunctuation
            | G::FinalPunctuation
            | G::OtherPunctuation
    )
}

fn is_cjk(c: char) -> bool {
    let u = c as u32;
    (0x4E00..=0x9FFF).contains(&u)
        || (0x3400..=0x4DBF).contains(&u)
        || (0x20000..=0x2A6DF).contains(&u)
        || (0x2A700..=0x2B73F).contains(&u)
        || (0x2B740..=0x2B81F).contains(&u)
        || (0x2B820..=0x2CEAF).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0x2F800..=0x2FA1F).contains(&u)
}

impl WordPiece {
    /// Build from `vocab.txt` contents (one token per line, id = line number).
    pub fn from_vocab_txt(vocab: &str) -> Result<Self, String> {
        let vocab: HashMap<String, u32> = vocab
            .lines()
            .enumerate()
            .map(|(i, t)| (t.to_string(), i as u32))
            .collect();
        let id = |t: &str| {
            vocab
                .get(t)
                .copied()
                .ok_or_else(|| format!("vocab lacks {t}"))
        };
        Ok(Self {
            cls: id("[CLS]")?,
            sep: id("[SEP]")?,
            unk: id("[UNK]")?,
            vocab,
            max_len: 512,
        })
    }

    /// Basic tokenisation: the word list before WordPiece.
    pub fn basic(&self, text: &str) -> Vec<String> {
        let mut cleaned = String::with_capacity(text.len());
        for c in text.chars() {
            if c == '\0' || c == '\u{FFFD}' || is_control(c) {
                continue;
            }
            if is_whitespace(c) {
                cleaned.push(' ');
            } else if is_cjk(c) {
                cleaned.push(' ');
                cleaned.push(c);
                cleaned.push(' ');
            } else {
                cleaned.push(c);
            }
        }
        let mut out = Vec::new();
        for tok in cleaned.split(' ').filter(|t| !t.is_empty()) {
            let lowered: String = tok
                .to_lowercase()
                .nfd()
                .filter(|c| get_general_category(*c) != G::NonspacingMark)
                .collect();
            let mut cur = String::new();
            for c in lowered.chars() {
                if is_punct(c) {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                    out.push(c.to_string());
                } else {
                    cur.push(c);
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
        }
        out
    }

    fn wordpiece(&self, word: &str, out: &mut Vec<u32>) {
        let chars: Vec<char> = word.chars().collect();
        if chars.len() > 100 {
            out.push(self.unk);
            return;
        }
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < chars.len() {
            let mut end = chars.len();
            let mut found = None;
            while start < end {
                let mut sub: String = chars[start..end].iter().collect();
                if start > 0 {
                    sub.insert_str(0, "##");
                }
                if let Some(&id) = self.vocab.get(&sub) {
                    found = Some(id);
                    break;
                }
                end -= 1;
            }
            match found {
                Some(id) => {
                    pieces.push(id);
                    start = end;
                }
                None => {
                    out.push(self.unk);
                    return;
                }
            }
        }
        out.extend(pieces);
    }

    /// `[CLS] tokens… [SEP]`, truncated so the total is at most `max_len`.
    pub fn encode(&self, text: &str) -> Ids {
        let mut ids = vec![self.cls];
        for w in self.basic(text) {
            self.wordpiece(&w, &mut ids);
            if ids.len() >= self.max_len - 1 {
                break;
            }
        }
        ids.truncate(self.max_len - 1);
        ids.push(self.sep);
        ids
    }
}
