//! Opt-in **Jev option** adapter (TypeSafe System One typed decisions).
//!
//! Jev answers *semantic* questions (Choice / Score / Noul) over
//! `POST /v1/systemone`. This crate is the small, self-contained adapter the
//! forum Workers share. It is deliberately inert unless a consumer turns it on:
//!
//! * the **flag** is read by the consumer (default off) and passed to
//!   [`resolve`]; with the flag off nothing is built and nothing leaves the
//!   process ([`Fallback::FlagOff`]);
//! * the endpoint is resolved in the contract order (explicit config, then the
//!   agentbox loopback proxy, then the vendor endpoint with a bearer key);
//! * every failure maps to a [`Fallback`] reason and the caller keeps its
//!   pre-change behaviour. Nothing here ever panics or returns a transport
//!   error to the caller;
//! * the transport is a trait ([`JevTransport`]) so the core runs natively in
//!   tests; the Workers `fetch` implementation lives behind the `worker`
//!   feature ([`fetch::WorkersFetch`]).
//!
//! Authority stays in the consumer: Jev output may only reorder, rank or
//! annotate. Request content is never logged; log [`Fallback::tag`] only.
#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

#[cfg(feature = "worker")]
pub mod fetch;

/// Default vendor endpoint (contract step 3).
pub const VENDOR_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Default vendor model alias.
pub const VENDOR_MODEL: &str = "jev-latest";
/// Hard deadline for interactive Worker paths, in milliseconds. 0 retries.
pub const DEFAULT_DEADLINE_MS: u32 = 4000;

/// Why a Jev call produced no usable answer. The consumer must then behave
/// exactly as it did before the Jev option existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fallback {
    /// The consumer's feature flag is off.
    FlagOff,
    /// No endpoint could be resolved (or a local-only consumer refused a
    /// non-local one).
    NoEndpoint,
    /// The hard deadline elapsed.
    Timeout,
    /// Transport failure or non-2xx status (`0` for a transport error).
    Http(u16),
    /// Unparseable body, missing answer IDs or keys, or a Choice key outside
    /// the offered set.
    Malformed,
    /// Confidence/probability below the consumer's acceptance threshold.
    LowConfidence,
}

impl Fallback {
    /// The single log token for this reason; never includes request content.
    pub fn tag(&self) -> String {
        match self {
            Fallback::FlagOff => "flag-off".into(),
            Fallback::NoEndpoint => "no-endpoint".into(),
            Fallback::Timeout => "timeout".into(),
            Fallback::Http(c) => format!("http-{c}"),
            Fallback::Malformed => "malformed".into(),
            Fallback::LowConfidence => "low-confidence".into(),
        }
    }
}

/// Transport-level failure reported by a [`JevTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Deadline elapsed.
    Timeout,
    /// Any other failure (DNS, TLS, abort, ...).
    Other,
}

/// Minimal HTTP POST seam. Implementations must enforce `deadline_ms`.
#[async_trait::async_trait(?Send)]
pub trait JevTransport {
    /// POST `body` (JSON) to `url`; `bearer` is `Some` only for the vendor
    /// endpoint. Returns `(status, body_text)`.
    async fn post_json(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &str,
        deadline_ms: u32,
    ) -> Result<(u16, String), TransportError>;
}

/// A resolved, usable endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct JevConfig {
    /// Full URL of the `systemone` route.
    pub endpoint: String,
    /// Model name sent in the request.
    pub model: String,
    /// Bearer key, `None` for the loopback proxy (it holds the vendor key).
    pub bearer: Option<String>,
    /// Hard deadline in milliseconds.
    pub deadline_ms: u32,
}

impl std::fmt::Debug for JevConfig {
    // The key must never reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JevConfig")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

/// Resolve the endpoint (contract §2, first match wins).
///
/// `lookup` reads a worker var or secret by name. `flag_var` is the
/// consumer's flag (must equal `1`/`true`). `local_only` consumers refuse
/// steps 2 and 3 unless `JEV_LOCAL=1` (or the explicit endpoint is declared
/// local the same way).
///
/// Recognised names: `JEV_ENDPOINT`, `JEV_MODEL`, `JEV_API_KEY_NAME` (name of
/// the secret holding the bearer key), `JEV_LOCAL`, `JEV_DEADLINE_MS`,
/// `AGENTBOX_SYSTEM_ONE_ENDPOINT`/`_MODEL`/`_PROXY`/`_BACKEND_LOCAL`,
/// `TYPESAFE_API_KEY`.
pub fn resolve(
    lookup: &dyn Fn(&str) -> Option<String>,
    flag_var: &str,
    local_only: bool,
) -> Result<JevConfig, Fallback> {
    let truthy = |name: &str| {
        lookup(name)
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false)
    };
    let nonempty = |name: &str| {
        lookup(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if !truthy(flag_var) {
        return Err(Fallback::FlagOff);
    }
    let deadline_ms = nonempty("JEV_DEADLINE_MS")
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v.clamp(100, DEFAULT_DEADLINE_MS))
        .unwrap_or(DEFAULT_DEADLINE_MS);
    let local = truthy("JEV_LOCAL");

    // 1. explicit config
    if let Some(endpoint) = nonempty("JEV_ENDPOINT") {
        if local_only && !local {
            return Err(Fallback::NoEndpoint);
        }
        let bearer = nonempty("JEV_API_KEY_NAME").and_then(|n| nonempty(&n));
        return Ok(JevConfig {
            endpoint,
            model: nonempty("JEV_MODEL").unwrap_or_else(|| VENDOR_MODEL.into()),
            bearer,
            deadline_ms,
        });
    }
    // 2. agentbox loopback proxy (no Authorization header)
    if truthy("AGENTBOX_SYSTEM_ONE_PROXY") {
        if let (Some(endpoint), Some(model)) = (
            nonempty("AGENTBOX_SYSTEM_ONE_ENDPOINT"),
            nonempty("AGENTBOX_SYSTEM_ONE_MODEL"),
        ) {
            if local_only && !truthy("AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL") {
                return Err(Fallback::NoEndpoint);
            }
            return Ok(JevConfig {
                endpoint,
                model,
                bearer: None,
                deadline_ms,
            });
        }
    }
    // 3. vendor endpoint, only with a key
    if let Some(key) = nonempty("TYPESAFE_API_KEY") {
        if local_only {
            return Err(Fallback::NoEndpoint);
        }
        return Ok(JevConfig {
            endpoint: VENDOR_ENDPOINT.into(),
            model: VENDOR_MODEL.into(),
            bearer: Some(key),
            deadline_ms,
        });
    }
    Err(Fallback::NoEndpoint)
}

/// One question in a System One request. `instructions` must carry the full
/// meaning: question IDs are not shown to the model.
#[derive(Debug, Clone, PartialEq)]
pub enum Question {
    /// Yes/no; the answer is the probability of yes.
    Noul {
        /// Full question text.
        instructions: String,
    },
    /// Ordered rubric; `criteria` is an ordered list (lowest level first).
    Score {
        /// Full question text.
        instructions: String,
        /// Ordered level descriptions.
        criteria: Vec<String>,
    },
    /// One of a keyed set; `criteria` is a map of key to description.
    Choice {
        /// Full question text.
        instructions: String,
        /// Key to description.
        criteria: BTreeMap<String, String>,
    },
}

impl Question {
    fn to_json(&self) -> Value {
        match self {
            Question::Noul { instructions } => {
                json!({"type": "noul", "instructions": instructions})
            }
            Question::Score {
                instructions,
                criteria,
            } => {
                json!({"type": "score", "instructions": instructions, "criteria": criteria})
            }
            Question::Choice {
                instructions,
                criteria,
            } => {
                json!({"type": "choice", "instructions": instructions, "criteria": criteria})
            }
        }
    }
}

/// A parsed answer, matching its question's type.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// Probability of yes, 0..=1.
    Noul(f64),
    /// Expected score (0-based level index, may fall between levels) and confidence.
    Score {
        /// Probability-weighted level.
        score: f64,
        /// Confidence 0..=1.
        confidence: f64,
    },
    /// Selected key and confidence.
    Choice {
        /// Selected criteria key.
        choice: String,
        /// Confidence 0..=1.
        confidence: f64,
    },
}

/// Build the request body (contract §5). Pure; unit-testable against the
/// archived OpenAPI schema.
pub fn build_request(model: &str, state: &impl Serialize, questions: &[(&str, Question)]) -> Value {
    let mut qs = Map::new();
    for (id, q) in questions {
        qs.insert((*id).to_string(), q.to_json());
    }
    json!({ "model": model, "state": state, "questions": qs })
}

/// Parse and validate a response against the questions that were asked.
/// Any missing ID, type mismatch or Choice key outside the offered set is
/// [`Fallback::Malformed`].
pub fn parse_response(
    body: &str,
    questions: &[(&str, Question)],
) -> Result<HashMap<String, Answer>, Fallback> {
    let v: Value = serde_json::from_str(body).map_err(|_| Fallback::Malformed)?;
    let answers = v
        .get("answers")
        .and_then(Value::as_object)
        .ok_or(Fallback::Malformed)?;
    let unit = |x: &Value| {
        x.as_f64()
            .filter(|f| f.is_finite() && (0.0..=1.0).contains(f))
    };
    let mut out = HashMap::new();
    for (id, q) in questions {
        let a = answers.get(*id).ok_or(Fallback::Malformed)?;
        let ty = a
            .get("type")
            .and_then(Value::as_str)
            .ok_or(Fallback::Malformed)?;
        let parsed = match (q, ty) {
            (Question::Noul { .. }, "noul") => {
                Answer::Noul(a.get("noul").and_then(unit).ok_or(Fallback::Malformed)?)
            }
            (Question::Score { criteria, .. }, "score") => {
                let score = a
                    .get("score")
                    .and_then(Value::as_f64)
                    .filter(|s| s.is_finite())
                    .ok_or(Fallback::Malformed)?;
                // Levels are 0-based by position (openapi: "starting at zero"),
                // so the expected score lies in [0, len - 1].
                if score < 0.0 || score > (criteria.len().saturating_sub(1)) as f64 {
                    return Err(Fallback::Malformed);
                }
                let confidence = a
                    .get("confidence")
                    .and_then(unit)
                    .ok_or(Fallback::Malformed)?;
                Answer::Score { score, confidence }
            }
            (Question::Choice { criteria, .. }, "choice") => {
                let choice = a
                    .get("choice")
                    .and_then(Value::as_str)
                    .ok_or(Fallback::Malformed)?;
                if !criteria.contains_key(choice) {
                    return Err(Fallback::Malformed);
                }
                let confidence = a
                    .get("confidence")
                    .and_then(unit)
                    .ok_or(Fallback::Malformed)?;
                Answer::Choice {
                    choice: choice.to_string(),
                    confidence,
                }
            }
            _ => return Err(Fallback::Malformed),
        };
        out.insert((*id).to_string(), parsed);
    }
    Ok(out)
}

/// Ask `questions` about `state`. Zero retries; never panics; returns a
/// [`Fallback`] on every failure so the caller can keep its old behaviour.
pub async fn ask<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    state: &impl Serialize,
    questions: &[(&str, Question)],
) -> Result<HashMap<String, Answer>, Fallback> {
    let body = serde_json::to_string(&build_request(&cfg.model, state, questions))
        .map_err(|_| Fallback::Malformed)?;
    let (status, text) = transport
        .post_json(&cfg.endpoint, cfg.bearer.as_deref(), &body, cfg.deadline_ms)
        .await
        .map_err(|e| match e {
            TransportError::Timeout => Fallback::Timeout,
            TransportError::Other => Fallback::Http(0),
        })?;
    if !(200..300).contains(&status) {
        return Err(Fallback::Http(status));
    }
    parse_response(&text, questions)
}

/// Minimal single-threaded executor for tests and doc examples, so the crate
/// needs no async runtime dependency.
#[doc(hidden)]
pub mod testutil {
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    /// Drive a future to completion (the mock transports never pend).
    pub fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    /// Canned transport. `reply` is returned verbatim; `requests` records
    /// every `(url, bearer, body)` for wire-shape assertions.
    pub struct Mock {
        /// What to return.
        pub reply: Result<(u16, String), TransportError>,
        /// Recorded calls.
        pub requests: std::cell::RefCell<Vec<(String, Option<String>, String)>>,
    }

    impl Mock {
        /// New mock with a canned reply.
        pub fn new(reply: Result<(u16, String), TransportError>) -> Self {
            Self {
                reply,
                requests: Default::default(),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl JevTransport for Mock {
        async fn post_json(
            &self,
            url: &str,
            bearer: Option<&str>,
            body: &str,
            _deadline_ms: u32,
        ) -> Result<(u16, String), TransportError> {
            self.requests
                .borrow_mut()
                .push((url.into(), bearer.map(Into::into), body.into()));
            self.reply.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn flag_off_never_resolves() {
        let e = env(&[("TYPESAFE_API_KEY", "k"), ("JEV_ENDPOINT", "http://x")]);
        assert_eq!(resolve(&e, "JEV_X", false), Err(Fallback::FlagOff));
        let e = env(&[("JEV_X", "0"), ("TYPESAFE_API_KEY", "k")]);
        assert_eq!(resolve(&e, "JEV_X", false), Err(Fallback::FlagOff));
    }

    #[test]
    fn flag_on_without_endpoint_is_no_endpoint() {
        let e = env(&[("JEV_X", "1")]);
        assert_eq!(resolve(&e, "JEV_X", false), Err(Fallback::NoEndpoint));
    }

    #[test]
    fn resolution_order() {
        let e = env(&[
            ("JEV_X", "1"),
            ("JEV_ENDPOINT", "http://explicit"),
            ("JEV_API_KEY_NAME", "MYKEY"),
            ("MYKEY", "secret"),
            ("AGENTBOX_SYSTEM_ONE_PROXY", "1"),
            ("AGENTBOX_SYSTEM_ONE_ENDPOINT", "http://proxy"),
            ("AGENTBOX_SYSTEM_ONE_MODEL", "m"),
            ("TYPESAFE_API_KEY", "v"),
        ]);
        let c = resolve(&e, "JEV_X", false).unwrap();
        assert_eq!(
            (c.endpoint.as_str(), c.bearer.as_deref()),
            ("http://explicit", Some("secret"))
        );

        let e = env(&[
            ("JEV_X", "1"),
            ("AGENTBOX_SYSTEM_ONE_PROXY", "1"),
            ("AGENTBOX_SYSTEM_ONE_ENDPOINT", "http://proxy"),
            ("AGENTBOX_SYSTEM_ONE_MODEL", "m"),
            ("TYPESAFE_API_KEY", "v"),
        ]);
        let c = resolve(&e, "JEV_X", false).unwrap();
        assert_eq!(
            (c.endpoint.as_str(), c.bearer.as_deref(), c.model.as_str()),
            ("http://proxy", None, "m")
        );

        let e = env(&[("JEV_X", "1"), ("TYPESAFE_API_KEY", "v")]);
        let c = resolve(&e, "JEV_X", false).unwrap();
        assert_eq!(
            (c.endpoint.as_str(), c.bearer.as_deref(), c.model.as_str()),
            (VENDOR_ENDPOINT, Some("v"), VENDOR_MODEL)
        );
    }

    #[test]
    fn local_only_refuses_non_local() {
        let e = env(&[("JEV_X", "1"), ("TYPESAFE_API_KEY", "v")]);
        assert_eq!(resolve(&e, "JEV_X", true), Err(Fallback::NoEndpoint));
        let e = env(&[("JEV_X", "1"), ("JEV_ENDPOINT", "http://h")]);
        assert_eq!(resolve(&e, "JEV_X", true), Err(Fallback::NoEndpoint));
        let e = env(&[
            ("JEV_X", "1"),
            ("JEV_ENDPOINT", "http://h"),
            ("JEV_LOCAL", "1"),
        ]);
        assert!(resolve(&e, "JEV_X", true).is_ok());
        let e = env(&[
            ("JEV_X", "1"),
            ("AGENTBOX_SYSTEM_ONE_PROXY", "1"),
            ("AGENTBOX_SYSTEM_ONE_ENDPOINT", "http://p"),
            ("AGENTBOX_SYSTEM_ONE_MODEL", "m"),
            ("AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL", "1"),
        ]);
        assert!(resolve(&e, "JEV_X", true).is_ok());
    }

    #[test]
    fn debug_redacts_key() {
        let c = JevConfig {
            endpoint: "e".into(),
            model: "m".into(),
            bearer: Some("s3cret".into()),
            deadline_ms: 1,
        };
        assert!(!format!("{c:?}").contains("s3cret"));
    }

    fn qs() -> Vec<(&'static str, Question)> {
        vec![
            (
                "n",
                Question::Noul {
                    instructions: "yes?".into(),
                },
            ),
            (
                "s",
                Question::Score {
                    instructions: "rate".into(),
                    criteria: vec!["a".into(), "b".into(), "c".into()],
                },
            ),
            (
                "c",
                Question::Choice {
                    instructions: "pick".into(),
                    criteria: [
                        ("x".to_string(), "X".to_string()),
                        ("none".to_string(), "N".to_string()),
                    ]
                    .into(),
                },
            ),
        ]
    }

    #[test]
    fn wire_shape_matches_contract() {
        let r = build_request("jev-latest", &json!({"q": "hi"}), &qs());
        assert_eq!(r["model"], "jev-latest");
        assert_eq!(r["state"]["q"], "hi");
        assert_eq!(r["questions"]["n"]["type"], "noul");
        assert!(
            r["questions"]["s"]["criteria"].is_array(),
            "Score criteria is an ordered list"
        );
        assert!(
            r["questions"]["c"]["criteria"].is_object(),
            "Choice criteria is a map"
        );
        assert_eq!(r["questions"]["c"]["criteria"]["none"], "N");
    }

    const GOOD: &str = r#"{"model":"jev","answers":{"n":{"type":"noul","noul":0.9},
        "s":{"type":"score","score":1.5,"confidence":0.8,"legend":{}},
        "c":{"type":"choice","choice":"x","confidence":0.7,"probabilities":{"x":0.8,"none":0.2}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    #[test]
    fn parses_good_response() {
        let m = Mock::new(Ok((200, GOOD.into())));
        let cfg = JevConfig {
            endpoint: "http://e".into(),
            model: "m".into(),
            bearer: Some("k".into()),
            deadline_ms: 10,
        };
        let a = block_on(ask(&m, &cfg, &json!({}), &qs())).unwrap();
        assert_eq!(a["n"], Answer::Noul(0.9));
        assert_eq!(
            a["c"],
            Answer::Choice {
                choice: "x".into(),
                confidence: 0.7
            }
        );
        let reqs = m.requests.borrow();
        assert_eq!(reqs[0].1.as_deref(), Some("k"));
    }

    #[test]
    fn every_failure_maps_to_a_fallback() {
        let cfg = JevConfig {
            endpoint: "http://e".into(),
            model: "m".into(),
            bearer: None,
            deadline_ms: 10,
        };
        let run = |reply| block_on(ask(&Mock::new(reply), &cfg, &json!({}), &qs())).unwrap_err();
        assert_eq!(run(Err(TransportError::Timeout)), Fallback::Timeout);
        assert_eq!(run(Err(TransportError::Other)), Fallback::Http(0));
        assert_eq!(run(Ok((429, "".into()))), Fallback::Http(429));
        assert_eq!(run(Ok((500, GOOD.into()))), Fallback::Http(500));
        assert_eq!(run(Ok((200, "not json".into()))), Fallback::Malformed);
        assert_eq!(
            run(Ok((200, r#"{"answers":{}}"#.into()))),
            Fallback::Malformed
        );
        // choice key outside the offered set
        let bad = GOOD.replace(r#""choice":"x""#, r#""choice":"zzz""#);
        assert_eq!(run(Ok((200, bad))), Fallback::Malformed);
        // type mismatch
        let bad = GOOD.replace(r#""type":"noul""#, r#""type":"score""#);
        assert_eq!(run(Ok((200, bad))), Fallback::Malformed);
    }

    #[test]
    fn tags_are_stable() {
        assert_eq!(Fallback::Http(503).tag(), "http-503");
        assert_eq!(Fallback::LowConfidence.tag(), "low-confidence");
    }
}
