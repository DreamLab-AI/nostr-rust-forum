//! Cloudflare Workers `fetch` transport with a hard deadline.
//!
//! The request is raced against a [`worker::Delay`]; when the delay wins the
//! `AbortController` is fired so the subrequest is cancelled, and
//! [`TransportError::Timeout`] is returned. No retries.

use crate::{JevTransport, TransportError};
use futures_util::future::{select, Either};
use std::time::Duration;
use worker::{AbortController, Delay, Fetch, Headers, Method, RequestInit};

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
            let text = resp.text().await.map_err(|_| TransportError::Other)?;
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
