//! Bluesky handle resolution with bounded latency and distinct upstream
//! failure modes (D16, §6.14).
//!
//! The whole client is a thin wrapper around `reqwest` configured with a
//! 5-second timeout. The point of this module is mapping upstream behavior
//! onto the project's three failure codes so handlers and logs can tell them
//! apart:
//!
//! - `BlueskyTimeout` — we waited 5s and got nothing. Operator-visible.
//! - `BlueskyUnavailable` — connection failure, malformed body, HTTP 5xx.
//! - `HandleResolveFailed` — Bluesky answered cleanly but the handle isn't
//!   one of theirs (4xx, or a 200 with no `did` field).

use std::time::Duration;

use serde::Deserialize;

use crate::error::{ApiError, ApiResult, Code};

const RESOLVE_URL: &str =
    "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle";
const TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = concat!("goodgirls-registry/", env!("CARGO_PKG_VERSION"));

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self { http })
    }

    /// Resolve a Bluesky handle to its DID. The input is normalized first
    /// (trim, drop a leading `@`, lowercase) — the worker accepted any of
    /// those shapes and we keep that contract.
    pub async fn resolve_handle(&self, raw_handle: &str) -> ApiResult<String> {
        let handle = normalize(raw_handle);

        let response = self
            .http
            .get(RESOLVE_URL)
            .query(&[("handle", handle.as_str())])
            .send()
            .await
            .map_err(|err| classify_send_error(&handle, err))?;

        let status = response.status();
        if status.is_client_error() {
            tracing::info!(handle = %handle, %status, "bluesky rejected handle");
            return Err(ApiError::new(Code::HandleResolveFailed));
        }
        if status.is_server_error() {
            tracing::warn!(handle = %handle, %status, "bluesky 5xx");
            return Err(ApiError::new(Code::BlueskyUnavailable));
        }

        let body: ResolveResponse = response.json().await.map_err(|err| {
            tracing::warn!(handle = %handle, %err, "bluesky response not parseable");
            ApiError::new(Code::BlueskyUnavailable)
        })?;

        body.did.ok_or_else(|| {
            tracing::info!(handle = %handle, "bluesky 200 without did");
            ApiError::new(Code::HandleResolveFailed)
        })
    }
}

fn normalize(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix('@').unwrap_or(trimmed);
    stripped.to_lowercase()
}

fn classify_send_error(handle: &str, err: reqwest::Error) -> ApiError {
    if err.is_timeout() {
        tracing::warn!(handle = %handle, %err, "bluesky timeout");
        ApiError::new(Code::BlueskyTimeout)
    } else {
        tracing::warn!(handle = %handle, %err, "bluesky unreachable");
        ApiError::new(Code::BlueskyUnavailable)
    }
}

#[derive(Deserialize)]
struct ResolveResponse {
    did: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_at_and_lowercases() {
        assert_eq!(normalize("  @Alice.bsky.SOCIAL "), "alice.bsky.social");
        assert_eq!(normalize("bob.bsky.social"), "bob.bsky.social");
        assert_eq!(normalize("@a"), "a");
    }
}
