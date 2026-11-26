//! Cloudflare Workers `fetch` transport with a hard deadline.
//!
//! The request and the body read are raced against a [`worker::Delay`]; when
//! the delay wins the `AbortController` is fired so the subrequest is
//! cancelled, and [`TransportError::Timeout`] is returned. No retries.
//!
//! Redirects are never followed (`redirect: manual`): the request may carry
//! `Authorization: Bearer <TYPESAFE_API_KEY>`, and a followed redirect would
//! hand it to whatever host the upstream names. A 3xx comes back as its status
//! and [`crate::ask`] maps it to [`crate::Fallback::Http`]. The body is read
//! with a running total and refused past [`MAX_RESPONSE_BYTES`].

use crate::body::{append_capped, content_length_ok};
use crate::{JevTransport, TransportError, MAX_RESPONSE_BYTES};
use futures_util::future::{select, Either};
use futures_util::TryStreamExt;
use std::time::Duration;
use worker::{
    AbortController, Delay, Fetch, Headers, Method, RequestInit, RequestRedirect, Response,
    ResponseBody,
};

/// `fetch`-based [`JevTransport`] for Workers.
#[derive(Default, Clone, Copy)]
pub struct WorkersFetch;

#[async_trait::async_trait(?Send)]
impl JevTransport for WorkersFetch {
    async fn post_json(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &str,
        deadline_ms: u32,
    ) -> Result<(u16, String), TransportError> {
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|_| TransportError::Other)?;
        if let Some(k) = bearer {
            headers
                .set("Authorization", &format!("Bearer {k}"))
                .map_err(|_| TransportError::Other)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual)
            .with_body(Some(body.into()));
        let req = worker::Request::new_with_init(url, &init).map_err(|_| TransportError::Other)?;
        let controller = AbortController::default();
        let signal = controller.signal();

        let work = async {
            let mut resp = Fetch::Request(req)
                .send_with_signal(&signal)
                .await
                .map_err(|_| TransportError::Other)?;
            let status = resp.status_code();
            let text = read_text_capped(&mut resp).await?;
            Ok::<_, TransportError>((status, text))
        };
        let timer = Delay::from(Duration::from_millis(u64::from(deadline_ms)));
        futures_util::pin_mut!(work);
        match select(work, timer).await {
            Either::Left((r, _)) => r,
            Either::Right((_, _)) => {
                controller.abort();
                Err(TransportError::Timeout)
            }
        }
    }
}

/// Read the body as text, refusing more than [`MAX_RESPONSE_BYTES`]. A stream
/// is consumed chunk by chunk and abandoned as soon as the cap is crossed.
async fn read_text_capped(resp: &mut Response) -> Result<String, TransportError> {
    let declared = resp.headers().get("Content-Length").ok().flatten();
    if !content_length_ok(declared.as_deref(), MAX_RESPONSE_BYTES) {
        return Err(TransportError::Other);
    }
    let mut buf = Vec::new();
    if matches!(resp.body(), ResponseBody::Stream(_)) {
        let mut stream = resp.stream().map_err(|_| TransportError::Other)?;
        while let Some(chunk) = stream.try_next().await.map_err(|_| TransportError::Other)? {
            append_capped(&mut buf, &chunk, MAX_RESPONSE_BYTES)?;
        }
    } else {
        let bytes = resp.bytes().await.map_err(|_| TransportError::Other)?;
        append_capped(&mut buf, &bytes, MAX_RESPONSE_BYTES)?;
    }
    // Invalid UTF-8 becomes replacement characters and then fails JSON parsing
    // in `ask` as `Fallback::Malformed`, which names the real problem.
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Build a `lookup` closure for [`crate::resolve`] over Worker vars and
/// secrets (vars first). Secret values are only ever returned to `resolve`,
/// which keeps them in a redacting [`crate::JevConfig`].
pub fn env_lookup(env: &worker::Env) -> impl Fn(&str) -> Option<String> + '_ {
    move |name| {
        env.var(name)
            .ok()
            .map(|v| v.to_string())
            .or_else(|| env.secret(name).ok().map(|s| s.to_string()))
    }
}
