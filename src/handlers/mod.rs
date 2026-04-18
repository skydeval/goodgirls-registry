//! HTTP handlers and cross-cutting request helpers.

pub mod manage;
pub mod public;

use axum::http::HeaderMap;
use serde::de::DeserializeOwned;

use crate::auth;
use crate::db;
use crate::error::{ApiError, ApiResult, Code};
use crate::state::AppState;

/// Parse a request body as JSON, mapping any failure onto `bad_json`.
/// We never surface serde error detail to the client.
pub fn parse_json<T: DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|_| ApiError::new(Code::BadJson))
}

/// Pull the raw value of a named cookie out of a `Cookie:` header. No fancy
/// parsing — the format is deterministic and we only ever read one cookie.
pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim());
        }
    }
    None
}

/// Return the subdomain portion of a `Host` header, or `None` for apex.
/// Strips the port suffix and only accepts a single-label subdomain.
pub fn host_subdomain<'a>(host: &'a str, base_domain: &str) -> Option<&'a str> {
    let host = host.split(':').next().unwrap_or(host);
    if host == base_domain {
        return None;
    }
    let suffix_len = base_domain.len() + 1; // for the leading '.'
    if host.len() <= suffix_len {
        return None;
    }
    let (sub, rest) = host.split_at(host.len() - suffix_len);
    if rest != format!(".{base_domain}") {
        return None;
    }
    if sub.is_empty() || sub.contains('.') {
        return None;
    }
    Some(sub)
}

/// Gate an admin endpoint: session cookie must resolve to an active row, and
/// the `X-CSRF-Token` header must match the token recorded on that row
/// (D8, §6.8). Returns the session's CSRF token for handlers that need to
/// echo it — but otherwise just enforces the guard.
pub async fn require_admin_session(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let session_id = cookie_value(headers, auth::SESSION_COOKIE_NAME)
        .ok_or_else(|| ApiError::new(Code::SessionInvalid))?;

    let Some(session) = db::find_active_session(&state.pool, session_id).await? else {
        return Err(ApiError::new(Code::SessionInvalid));
    };

    let csrf = headers
        .get(auth::CSRF_HEADER_NAME)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::new(Code::CsrfInvalid))?;

    if !auth::hashes_equal(csrf, &session.csrf_token) {
        return Err(ApiError::new(Code::CsrfInvalid));
    }

    Ok(session.csrf_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn cookies(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn cookie_parser_finds_named_value() {
        let h = cookies("session=abcd; theme=dark");
        assert_eq!(cookie_value(&h, "session"), Some("abcd"));
        assert_eq!(cookie_value(&h, "theme"), Some("dark"));
        assert_eq!(cookie_value(&h, "nope"), None);
    }

    #[test]
    fn cookie_parser_handles_whitespace() {
        let h = cookies("  session = abcd  ;theme=dark");
        assert_eq!(cookie_value(&h, "session"), Some("abcd"));
    }

    #[test]
    fn cookie_parser_missing_header() {
        assert_eq!(cookie_value(&HeaderMap::new(), "session"), None);
    }

    #[test]
    fn host_subdomain_extracts_single_label() {
        assert_eq!(host_subdomain("alice.goodgirls.onl", "goodgirls.onl"), Some("alice"));
        assert_eq!(host_subdomain("alice.goodgirls.onl:8080", "goodgirls.onl"), Some("alice"));
    }

    #[test]
    fn host_subdomain_rejects_apex_and_multilabel() {
        assert_eq!(host_subdomain("goodgirls.onl", "goodgirls.onl"), None);
        assert_eq!(host_subdomain("a.b.goodgirls.onl", "goodgirls.onl"), None);
        assert_eq!(host_subdomain("notgoodgirls.onl", "goodgirls.onl"), None);
        assert_eq!(host_subdomain("", "goodgirls.onl"), None);
    }
}
