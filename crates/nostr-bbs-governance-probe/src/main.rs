//! `nostr-bbs-governance-probe` — run the ADR-2011 M4 probe suite against a
//! live relay and auth API, writing one JSON receipt per probe.
//!
//! ```text
//! nostr-bbs-governance-probe \
//!     --relay wss://<relay> --auth-api https://<auth-api> \
//!     --key-var JUNKIEJARVIS_PRIVKEY_HEX --out .claude/evidence/m4-YYYY-MM-DD
//! ```
//!
//! The signing key is read from the named environment variable and never
//! printed. The signer must be a registered agent on the relay and must NOT be
//! an admin: several probes assert that an agent is refused. Exit status is 0
//! only when every probe passed; any failure or not-run probe exits 1.
//!
//! The binary is native-only; on wasm32 it compiles to an empty `main`.

#[cfg(not(target_arch = "wasm32"))]
mod net;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    rt.block_on(cli::run())
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
mod cli {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::Duration;

    use nostr_bbs_governance_probe as suite;
    use serde_json::{json, Value};
    use suite::{ProbeReceipt, ProbeRun, Verdict};

    use crate::net::{now_secs, Http, Identity, RelaySession};

    struct Args {
        relay: String,
        auth_api: String,
        key_var: String,
        out: PathBuf,
        run_id: Option<String>,
        keep_open: bool,
        list_cases: bool,
    }

    const USAGE: &str =
        "usage: nostr-bbs-governance-probe --relay <wss-url> --auth-api <https-url> \
        --out <dir> [--key-var <ENV>] [--run-id <id>] [--keep-open]\n       \
        nostr-bbs-governance-probe --auth-api <https-url> --list-cases [--key-var <ENV>]";

    fn parse_args() -> Result<Args, String> {
        let mut relay = None;
        let mut auth_api = None;
        let mut out = None;
        let mut key_var = "JUNKIEJARVIS_PRIVKEY_HEX".to_string();
        let mut run_id = None;
        let mut keep_open = false;
        let mut list_cases = false;
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            let mut val = || it.next().ok_or(format!("{a} needs a value"));
            match a.as_str() {
                "--relay" => relay = Some(val()?),
                "--auth-api" => auth_api = Some(val()?.trim_end_matches('/').to_string()),
                "--out" => out = Some(PathBuf::from(val()?)),
                "--key-var" => key_var = val()?,
                "--run-id" => run_id = Some(val()?),
                "--keep-open" => keep_open = true,
                "--list-cases" => list_cases = true,
                "-h" | "--help" => return Err(USAGE.into()),
                other => return Err(format!("unknown argument {other}\n{USAGE}")),
            }
        }
        if list_cases {
            return Ok(Args {
                relay: relay.unwrap_or_default(),
                auth_api: auth_api.ok_or(USAGE)?,
                out: out.unwrap_or_default(),
                key_var,
                run_id,
                keep_open,
                list_cases,
            });
        }
        Ok(Args {
            relay: relay.ok_or(USAGE)?,
            auth_api: auth_api.ok_or(USAGE)?,
            out: out.ok_or(USAGE)?,
            key_var,
            run_id,
            keep_open,
            list_cases,
        })
    }

    /// Read-only: print every open case with its stored effective tier, so an
    /// operator can find the high-tier case a human must decide.
    async fn list_cases(args: &Args, identity: &Identity, http: &Http) -> ExitCode {
        let url = format!("{}/api/governance/cases?state=open", args.auth_api);
        match http.get_signed(identity, &url).await {
            Ok(a) if a.status == 200 => {
                let cases = a.body["cases"].as_array().cloned().unwrap_or_default();
                for c in &cases {
                    println!(
                        "{}\t{}\t(declared {})\t{}\t{}",
                        c["id"].as_str().unwrap_or(""),
                        c["effective_tier"].as_str().unwrap_or("-"),
                        c["declared_tier"].as_str().unwrap_or("-"),
                        c["created_by"]
                            .as_str()
                            .map(|p| &p[..p.len().min(12)])
                            .unwrap_or(""),
                        c["title"].as_str().unwrap_or(""),
                    );
                }
                println!("{} open case(s)", cases.len());
                ExitCode::SUCCESS
            }
            Ok(a) => {
                eprintln!("{url} answered {} {}", a.status, a.body);
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("{url}: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Default run id from the clock: `20261002t131011z`.
    fn clock_run_id(secs: u64) -> String {
        suite::rfc3339(secs)
            .replace(['-', ':'], "")
            .to_ascii_lowercase()
    }

    struct Recorder {
        receipts: Vec<ProbeReceipt>,
    }

    impl Recorder {
        #[allow(clippy::too_many_arguments)]
        fn record(
            &mut self,
            id: &str,
            title: &str,
            clause: &str,
            at: u64,
            request: Value,
            response: Value,
            event_ids: Vec<String>,
            verdict: Verdict,
        ) {
            let mark = match &verdict {
                Verdict::Pass => "PASS".to_string(),
                Verdict::Fail(w) => format!("FAIL — {w}"),
                Verdict::NotRun(w) => format!("NOT RUN — {w}"),
            };
            println!("{id} {title}: {mark}");
            self.receipts.push(ProbeReceipt {
                id: id.into(),
                title: title.into(),
                clause: clause.into(),
                at: suite::rfc3339(at),
                request,
                response,
                event_ids,
                verdict,
            });
        }
    }

    fn https_of(relay: &str) -> String {
        relay
            .replacen("wss://", "https://", 1)
            .replacen("ws://", "http://", 1)
    }

    /// Fetch a case, retrying while the relay's projection catches up.
    async fn fetch_case(
        http: &Http,
        id: &Identity,
        url: &str,
    ) -> Result<crate::net::HttpAnswer, String> {
        let mut last = http.get_signed(id, url).await?;
        for _ in 0..6 {
            if last.status != 404 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            last = http.get_signed(id, url).await?;
        }
        Ok(last)
    }

    pub async fn run() -> ExitCode {
        let args = match parse_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        let identity = match Identity::from_env(&args.key_var) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        if args.list_cases {
            return match Http::new() {
                Ok(http) => list_cases(&args, &identity, &http).await,
                Err(e) => {
                    eprintln!("http client: {e}");
                    ExitCode::from(2)
                }
            };
        }
        let started = now_secs();
        let run = match ProbeRun::new(&args.run_id.clone().unwrap_or_else(|| clock_run_id(started)))
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        let http = match Http::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("http client: {e}");
                return ExitCode::from(2);
            }
        };
        let pk = identity.pubkey().to_string();
        println!(
            "M4 probe run {} as agent {pk} against {} / {}",
            run.id(),
            args.relay,
            args.auth_api
        );
        let mut rec = Recorder {
            receipts: Vec::new(),
        };

        // P01 — NIP-11.
        let nip11_url = https_of(&args.relay);
        let at = now_secs();
        match http.nip11(&nip11_url).await {
            Ok(a) => {
                let v = if a.status == 200 {
                    suite::judge_nip11(&a.body)
                } else {
                    Verdict::Fail(format!("NIP-11 answered {}", a.status))
                };
                rec.record(
                    "P01",
                    "NIP-11 advertises the escalation default",
                    "ADR-2011 §3",
                    at,
                    json!({"method": "GET", "url": nip11_url, "accept": "application/nostr+json"}),
                    a.to_json(),
                    vec![],
                    v,
                );
            }
            Err(e) => rec.record(
                "P01",
                "NIP-11 advertises the escalation default",
                "ADR-2011 §3",
                at,
                json!({"method": "GET", "url": nip11_url}),
                Value::Null,
                vec![],
                Verdict::NotRun(format!("transport: {e}")),
            ),
        }

        // P02 — reviewers route: gated unsigned, reachable signed.
        let url = format!("{}/api/governance/reviewers", args.auth_api);
        let at = now_secs();
        // Whether the signer is an admin is recorded, not assumed: it decides
        // which rule P08/P09 reach (admission vs the rationale/human guards).
        let mut signer_is_admin = None;
        match (
            http.get_plain(&url).await,
            http.get_signed(&identity, &url).await,
        ) {
            (Ok(u), Ok(a)) => {
                signer_is_admin = Some(a.status == 200);
                let v = suite::judge_reviewers_route(u.status, a.status, &a.body);
                rec.record(
                    "P02",
                    "reviewers route deployed and gated",
                    "ADR-2011 FR6.1",
                    at,
                    json!({"unsigned": {"method": "GET", "url": url},
                           "signed": {"method": "GET", "url": url, "auth": "NIP-98 (probe agent)"}}),
                    json!({"unsigned": u.to_json(), "signed": a.to_json()}),
                    vec![],
                    v,
                );
            }
            (u, a) => rec.record(
                "P02",
                "reviewers route deployed and gated",
                "ADR-2011 FR6.1",
                at,
                json!({"method": "GET", "url": url}),
                json!({"unsigned": u.err(), "signed": a.err()}),
                vec![],
                Verdict::NotRun("transport".into()),
            ),
        }

        // P03 — application route parses the ADR-2011 stage vocabulary.
        let url = format!(
            "{}/api/governance/receipts/{}/application",
            args.auth_api,
            "0".repeat(64)
        );
        let body = json!({"stage": "m4-probe-not-a-stage", "acknowledgement": "ADR-2011 M4 probe"});
        let at = now_secs();
        match http.post_signed(&identity, &url, &body).await {
            Ok(a) => {
                let v = suite::judge_application_unknown_stage(a.status, &a.body);
                rec.record(
                    "P03",
                    "application-receipt route deployed with the stage ladder",
                    "ADR-2011 §5 / FR4.1",
                    at,
                    json!({"method": "POST", "url": url, "body": body, "auth": "NIP-98 (agent)"}),
                    a.to_json(),
                    vec![],
                    v,
                );
            }
            Err(e) => rec.record(
                "P03",
                "application-receipt route deployed with the stage ladder",
                "ADR-2011 §5 / FR4.1",
                at,
                json!({"method": "POST", "url": url, "body": body}),
                Value::Null,
                vec![],
                Verdict::NotRun(format!("transport: {e}")),
            ),
        }

        // Relay probes need a session.
        let mut session = match RelaySession::connect(&args.relay, &identity).await {
            Ok(s) => s,
            Err(e) => {
                for (pid, title) in [
                    ("P04", "probe panel published"),
                    ("P05", "probe request published"),
                    ("P06", "effective tier stamped by the operator's triple"),
                    ("P07", "probe tag withheld from the tag index"),
                    ("P08", "rationale-less response refused before storage"),
                    ("P09", "system-decider response cannot close a high case"),
                    ("P10", "neither response changed the case"),
                    ("P11", "probe request withdrawn"),
                ] {
                    rec.record(
                        pid,
                        title,
                        "ADR-2011",
                        now_secs(),
                        json!({"relay": args.relay}),
                        Value::Null,
                        vec![],
                        Verdict::NotRun(format!("relay session: {e}")),
                    );
                }
                return finish(&args, &run, &pk, started, rec.receipts);
            }
        };
        println!(
            "relay session open (NIP-42 authenticated: {})",
            session.authenticated
        );

        // P04 — probe panel.
        let at = now_secs();
        let panel = match identity.sign(suite::panel_event(&pk, at)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("sign: {e}");
                return ExitCode::from(2);
            }
        };
        let panel_ok = match session.publish(&panel, &identity).await {
            Ok(ok) => {
                let v = suite::judge_accepted(ok.accepted, &ok.message);
                let pass = v.is_pass();
                rec.record(
                    "P04",
                    "probe panel published",
                    "ADR-2011 §1 / §6",
                    at,
                    json!({"event": panel}),
                    json!({"ok": ok.accepted, "message": ok.message}),
                    vec![panel.id.clone()],
                    v,
                );
                pass
            }
            Err(e) => {
                rec.record(
                    "P04",
                    "probe panel published",
                    "ADR-2011 §1 / §6",
                    at,
                    json!({"event": panel}),
                    Value::Null,
                    vec![panel.id.clone()],
                    Verdict::NotRun(format!("transport: {e}")),
                );
                false
            }
        };

        // P05 — probe request.
        let at = now_secs();
        let request = match identity.sign(suite::request_event(&pk, &run, at)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("sign: {e}");
                return ExitCode::from(2);
            }
        };
        let request_ok = if !panel_ok {
            rec.record(
                "P05",
                "probe request published",
                "ADR-2011 §1",
                at,
                json!({"event": request}),
                Value::Null,
                vec![],
                Verdict::NotRun("probe panel not accepted (P04)".into()),
            );
            false
        } else {
            match session.publish(&request, &identity).await {
                Ok(ok) => {
                    let v = suite::judge_accepted(ok.accepted, &ok.message);
                    let pass = v.is_pass();
                    rec.record(
                        "P05",
                        "probe request published",
                        "ADR-2011 §1",
                        at,
                        json!({"event": request}),
                        json!({"ok": ok.accepted, "message": ok.message}),
                        vec![request.id.clone()],
                        v,
                    );
                    pass
                }
                Err(e) => {
                    rec.record(
                        "P05",
                        "probe request published",
                        "ADR-2011 §1",
                        at,
                        json!({"event": request}),
                        Value::Null,
                        vec![request.id.clone()],
                        Verdict::NotRun(format!("transport: {e}")),
                    );
                    false
                }
            }
        };

        let case_url = format!("{}/api/governance/cases/{}", args.auth_api, run.case_d());
        let blocked = |why: &str| Verdict::NotRun(why.to_string());

        // P06 — projection.
        let at = now_secs();
        if request_ok {
            match fetch_case(&http, &identity, &case_url).await {
                Ok(a) => {
                    let v = if a.status == 200 {
                        suite::judge_case_projection(&a.body["case"], &run, &pk)
                    } else {
                        Verdict::Fail(format!("case read answered {}", a.status))
                    };
                    rec.record(
                        "P06",
                        "effective tier stamped by the operator's triple",
                        "ADR-2011 §2 / §3 / §6",
                        at,
                        json!({"method": "GET", "url": case_url, "auth": "NIP-98 (agent)"}),
                        a.to_json(),
                        vec![request.id.clone()],
                        v,
                    );
                }
                Err(e) => rec.record(
                    "P06",
                    "effective tier stamped by the operator's triple",
                    "ADR-2011 §2 / §3 / §6",
                    at,
                    json!({"method": "GET", "url": case_url}),
                    Value::Null,
                    vec![],
                    Verdict::NotRun(format!("transport: {e}")),
                ),
            }
        } else {
            rec.record(
                "P06",
                "effective tier stamped by the operator's triple",
                "ADR-2011 §2 / §3 / §6",
                at,
                json!({"url": case_url}),
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        }

        // P07 — tag index.
        let at = now_secs();
        if request_ok {
            let by_probe = json!({"kinds": [31402], "#probe": [run.probe_digest()], "limit": 10});
            let by_d =
                json!({"kinds": [31402], "authors": [pk], "#d": [run.case_d()], "limit": 10});
            let a = session.query(by_probe.clone()).await;
            let b = session.query(by_d.clone()).await;
            match (a, b) {
                (Ok(a), Ok(b)) => {
                    let v = suite::judge_probe_not_indexed(a.len(), b.len());
                    let ids = b.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
                    rec.record(
                        "P07",
                        "probe tag withheld from the tag index",
                        "ADR-2011 §6",
                        at,
                        json!({"req_probe": by_probe, "req_control": by_d}),
                        json!({"probe_matches": a.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
                               "control_matches": ids}),
                        ids.clone(),
                        v,
                    );
                }
                (a, b) => rec.record(
                    "P07",
                    "probe tag withheld from the tag index",
                    "ADR-2011 §6",
                    at,
                    json!({"req_probe": by_probe, "req_control": by_d}),
                    json!({"probe": a.err(), "control": b.err()}),
                    vec![],
                    Verdict::NotRun("REQ failed".into()),
                ),
            }
        } else {
            rec.record(
                "P07",
                "probe tag withheld from the tag index",
                "ADR-2011 §6",
                at,
                Value::Null,
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        }

        // P08 — a rationale-less 31403 on the high case.
        let at = now_secs();
        let mut stored_responses: Vec<String> = Vec::new();
        if request_ok {
            let resp = match identity.sign(suite::response_event(&pk, &run, &request.id, at)) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("sign: {e}");
                    return ExitCode::from(2);
                }
            };
            match session.publish(&resp, &identity).await {
                Ok(ok) => {
                    if ok.accepted {
                        stored_responses.push(resp.id.clone());
                    }
                    let v = suite::judge_agent_response_refused(ok.accepted, &ok.message);
                    rec.record(
                        "P08",
                        "rationale-less response refused before storage",
                        "ADR-2011 §4 / FR2.2",
                        at,
                        json!({"event": resp, "signer_is_admin": signer_is_admin}),
                        json!({"ok": ok.accepted, "message": ok.message}),
                        vec![resp.id.clone()],
                        v,
                    );
                }
                Err(e) => rec.record(
                    "P08",
                    "rationale-less response refused before storage",
                    "ADR-2011 §4 / FR2.2",
                    at,
                    json!({"event": resp}),
                    Value::Null,
                    vec![resp.id.clone()],
                    Verdict::NotRun(format!("transport: {e}")),
                ),
            }
        } else {
            rec.record(
                "P08",
                "rationale-less response refused before storage",
                "ADR-2011 §4 / FR2.2",
                at,
                Value::Null,
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        }

        // P09 — a system-decider 31403 with a valid rationale.
        let at = now_secs();
        if request_ok {
            let resp = match identity.sign(suite::system_response_event(&pk, &run, &request.id, at))
            {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("sign: {e}");
                    return ExitCode::from(2);
                }
            };
            match session.publish(&resp, &identity).await {
                Ok(ok) => {
                    if ok.accepted {
                        stored_responses.push(resp.id.clone());
                    }
                    let v = suite::judge_system_response(ok.accepted, &ok.message);
                    rec.record(
                        "P09",
                        "system-decider response cannot close a high case",
                        "ADR-2011 §4",
                        at,
                        json!({"event": resp, "signer_is_admin": signer_is_admin}),
                        json!({"ok": ok.accepted, "message": ok.message,
                               "note": "if stored, P10 asserts the projection refused it"}),
                        vec![resp.id.clone()],
                        v,
                    );
                }
                Err(e) => rec.record(
                    "P09",
                    "system-decider response cannot close a high case",
                    "ADR-2011 §4",
                    at,
                    json!({"event": resp}),
                    Value::Null,
                    vec![resp.id.clone()],
                    Verdict::NotRun(format!("transport: {e}")),
                ),
            }
        } else {
            rec.record(
                "P09",
                "system-decider response cannot close a high case",
                "ADR-2011 §4",
                at,
                Value::Null,
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        }

        // P10 — nothing changed. Give the projection time to have run.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let at = now_secs();
        if request_ok {
            match http.get_signed(&identity, &case_url).await {
                Ok(a) => {
                    let v = if a.status == 200 {
                        suite::judge_case_unchanged(&a.body["case"])
                    } else {
                        Verdict::Fail(format!("case read answered {}", a.status))
                    };
                    rec.record(
                        "P10",
                        "neither response changed the case",
                        "ADR-2011 §4",
                        at,
                        json!({"method": "GET", "url": case_url, "auth": "NIP-98 (probe agent)"}),
                        a.to_json(),
                        stored_responses.clone(),
                        v,
                    );
                }
                Err(e) => rec.record(
                    "P10",
                    "neither response changed the case",
                    "ADR-2011 §4",
                    at,
                    json!({"url": case_url}),
                    Value::Null,
                    vec![],
                    Verdict::NotRun(format!("transport: {e}")),
                ),
            }
        } else {
            rec.record(
                "P10",
                "neither response changed the case",
                "ADR-2011 §4",
                at,
                Value::Null,
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        }

        // P11 — withdraw the probe request and any stored response.
        let at = now_secs();
        if !request_ok {
            rec.record(
                "P11",
                "probe request withdrawn",
                "clean-up",
                at,
                Value::Null,
                Value::Null,
                vec![],
                blocked("probe request not accepted (P05)"),
            );
        } else if args.keep_open {
            println!("P11 skipped: --keep-open leaves the probe case on the panel");
        } else {
            let unsigned = suite::withdrawal_event(&pk, &run, &request.id, &stored_responses, at);
            match identity.sign(unsigned) {
                Ok(del) => match session.publish(&del, &identity).await {
                    Ok(ok) => {
                        let v = suite::judge_accepted(ok.accepted, &ok.message);
                        rec.record(
                            "P11",
                            "probe request withdrawn",
                            "clean-up",
                            at,
                            json!({"event": del}),
                            json!({"ok": ok.accepted, "message": ok.message}),
                            vec![del.id.clone()],
                            v,
                        );
                    }
                    Err(e) => rec.record(
                        "P11",
                        "probe request withdrawn",
                        "clean-up",
                        at,
                        json!({"event": del}),
                        Value::Null,
                        vec![del.id.clone()],
                        Verdict::NotRun(format!("transport: {e}")),
                    ),
                },
                Err(e) => {
                    eprintln!("sign: {e}");
                    return ExitCode::from(2);
                }
            }
        }

        finish(&args, &run, &pk, started, rec.receipts)
    }

    fn finish(
        args: &Args,
        run: &ProbeRun,
        pk: &str,
        started: u64,
        receipts: Vec<ProbeReceipt>,
    ) -> ExitCode {
        let dir = args.out.join(format!("run-{}", run.id()));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("create {}: {e}", dir.display());
            return ExitCode::from(2);
        }
        for r in &receipts {
            let path = dir.join(format!("{}.json", r.id));
            let text = serde_json::to_string_pretty(r).unwrap_or_default();
            if let Err(e) = std::fs::write(&path, text + "\n") {
                eprintln!("write {}: {e}", path.display());
                return ExitCode::from(2);
            }
        }
        let passed = suite::suite_passed(&receipts);
        let summary = json!({
            "suite": "ADR-2011 M4 probe suite (PRD-augmentation-conditions M4)",
            "tool": concat!("nostr-bbs-governance-probe ", env!("CARGO_PKG_VERSION")),
            "run_id": run.id(),
            "started_at": suite::rfc3339(started),
            "finished_at": suite::rfc3339(now_secs()),
            "relay": args.relay,
            "auth_api": args.auth_api,
            "probe_agent": pk,
            "probe_panel": suite::panel_coordinate(pk),
            "probe_case": run.case_d(),
            "passed": passed,
            "verdicts": receipts.iter().map(|r| json!({"id": r.id, "verdict": r.verdict,
                "event_ids": r.event_ids})).collect::<Vec<_>>(),
        });
        let path = dir.join("summary.json");
        if let Err(e) = std::fs::write(
            &path,
            serde_json::to_string_pretty(&summary).unwrap_or_default() + "\n",
        ) {
            eprintln!("write {}: {e}", path.display());
            return ExitCode::from(2);
        }
        println!(
            "{} — receipts in {}",
            if passed { "M4 PASSED" } else { "M4 NOT PASSED" },
            dir.display()
        );
        if passed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}
