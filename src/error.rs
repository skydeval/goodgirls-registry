//! Uniform response shape for every endpoint: `{ok, code, ...}`.
//!
//! Success bodies carry `ok: true` and a flattened payload. Error bodies carry
//! `ok: false`, a stable `code`, and a human-readable `error`. Inside the
//! authenticated admin space, handlers may attach a `detail` field — the
//! technical second layer behind the mystical primary message (D17).

use std::borrow::Cow;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Stable machine-readable identifier for every response the service can emit.
/// Success and error variants share this enum so both halves of the contract
/// live in one place (D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    // -- success --
    Registered,
    AdminRegistered,
    Renamed,
    Deleted,
    Listed,
    Wiped,
    Exported,
    LoggedIn,

    // -- request shape --
    BadJson,
    MissingFields,
    ConfirmRequired,

    // -- subdomain validation (D1) --
    SubdomainTooShort,
    SubdomainTooLong,
    SubdomainInvalidChars,
    SubdomainHyphenRules,
    SubdomainReserved,
    SubdomainBlocked,

    // -- conflict / state --
    SubdomainTaken,
    DidHasHandle,
    DidHasSecret,
    HandleNotFound,
    DidNotFound,

    // -- authentication --
    WrongKey,
    Unauthorized,
    CsrfInvalid,
    SessionInvalid,

    // -- upstream (Bluesky) --
    HandleResolveFailed,
    BlueskyUnavailable,
    BlueskyTimeout,

    // -- generic --
    NotFound,
    InternalError,
}

impl Code {
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::Registered => "registered",
            Code::AdminRegistered => "admin_registered",
            Code::Renamed => "renamed",
            Code::Deleted => "deleted",
            Code::Listed => "listed",
            Code::Wiped => "wiped",
            Code::Exported => "exported",
            Code::LoggedIn => "logged_in",

            Code::BadJson => "bad_json",
            Code::MissingFields => "missing_fields",
            Code::ConfirmRequired => "confirm_required",

            Code::SubdomainTooShort => "subdomain_too_short",
            Code::SubdomainTooLong => "subdomain_too_long",
            Code::SubdomainInvalidChars => "subdomain_invalid_chars",
            Code::SubdomainHyphenRules => "subdomain_hyphen_rules",
            Code::SubdomainReserved => "subdomain_reserved",
            Code::SubdomainBlocked => "subdomain_blocked",

            Code::SubdomainTaken => "subdomain_taken",
            Code::DidHasHandle => "did_has_handle",
            Code::DidHasSecret => "did_has_secret",
            Code::HandleNotFound => "handle_not_found",
            Code::DidNotFound => "did_not_found",

            Code::WrongKey => "wrong_key",
            Code::Unauthorized => "unauthorized",
            Code::CsrfInvalid => "csrf_invalid",
            Code::SessionInvalid => "session_invalid",

            Code::HandleResolveFailed => "handle_resolve_failed",
            Code::BlueskyUnavailable => "bluesky_unavailable",
            Code::BlueskyTimeout => "bluesky_timeout",

            Code::NotFound => "not_found",
            Code::InternalError => "internal_error",
        }
    }

    /// Default HTTP status for this code. Each code has exactly one natural
    /// status; handlers almost never need to override it.
    pub const fn status(self) -> StatusCode {
        match self {
            Code::Registered
            | Code::AdminRegistered
            | Code::Renamed
            | Code::Deleted
            | Code::Listed
            | Code::Wiped
            | Code::Exported
            | Code::LoggedIn => StatusCode::OK,

            Code::BadJson
            | Code::MissingFields
            | Code::ConfirmRequired
            | Code::SubdomainTooShort
            | Code::SubdomainTooLong
            | Code::SubdomainInvalidChars
            | Code::SubdomainHyphenRules
            | Code::SubdomainReserved
            | Code::SubdomainBlocked
            | Code::HandleResolveFailed => StatusCode::BAD_REQUEST,

            Code::WrongKey
            | Code::Unauthorized
            | Code::CsrfInvalid
            | Code::SessionInvalid => StatusCode::UNAUTHORIZED,

            Code::DidHasHandle | Code::DidHasSecret => StatusCode::FORBIDDEN,

            Code::SubdomainTaken => StatusCode::CONFLICT,

            Code::HandleNotFound | Code::DidNotFound | Code::NotFound => StatusCode::NOT_FOUND,

            Code::BlueskyUnavailable => StatusCode::BAD_GATEWAY,
            Code::BlueskyTimeout => StatusCode::GATEWAY_TIMEOUT,

            Code::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Canonical user-facing message for error codes. Success codes return an
    /// empty string — their payload is the useful part.
    pub const fn default_message(self) -> &'static str {
        match self {
            Code::Registered
            | Code::AdminRegistered
            | Code::Renamed
            | Code::Deleted
            | Code::Listed
            | Code::Wiped
            | Code::Exported
            | Code::LoggedIn => "",

            Code::BadJson => "request body is not valid JSON",
            Code::MissingFields => "required fields missing",
            Code::ConfirmRequired => "confirmation string required",

            Code::SubdomainTooShort => "subdomain must be at least 3 characters",
            Code::SubdomainTooLong => "subdomain must be at most 49 characters",
            Code::SubdomainInvalidChars => {
                "subdomain may only contain lowercase letters, digits, and hyphens"
            }
            Code::SubdomainHyphenRules => {
                "subdomain may not start or end with a hyphen, or contain consecutive hyphens"
            }
            Code::SubdomainReserved => "that subdomain is reserved",
            Code::SubdomainBlocked => "that subdomain is not allowed",

            Code::SubdomainTaken => "that handle is already claimed",
            Code::DidHasHandle => {
                "this bluesky account already has a goodgirls handle — use the manage page"
            }
            Code::DidHasSecret => "this bluesky account already has a goodgirls key",
            Code::HandleNotFound => "that handle does not exist",
            // Admin-only path. The mystical primary; the handler attaches
            // SQL-shaped detail as the second layer (D17).
            Code::DidNotFound => "the void found nothing to swallow",

            Code::WrongKey => "the sigil does not resonate",
            Code::Unauthorized => "unauthorized",
            Code::CsrfInvalid => "csrf token is missing or invalid",
            Code::SessionInvalid => "session is missing or expired",

            Code::HandleResolveFailed => "could not resolve that bluesky handle",
            Code::BlueskyUnavailable => "bluesky is not responding right now",
            Code::BlueskyTimeout => "bluesky took too long to answer",

            Code::NotFound => "not found",
            Code::InternalError => "something went wrong on our side",
        }
    }
}

/// Any failure returned from a handler. Convert into an axum response via
/// `IntoResponse`, which renders the uniform error body.
#[derive(Debug)]
pub struct ApiError {
    pub code: Code,
    pub status: StatusCode,
    pub message: Cow<'static, str>,
    /// Technical layer surfaced only in admin contexts (D17). Handlers opt in
    /// by setting this; `IntoResponse` serializes it verbatim when present.
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            status: code.status(),
            message: Cow::Borrowed(code.default_message()),
            detail: None,
        }
    }

    pub fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        self.message = message.into();
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(Code::InternalError).with_detail(detail)
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    ok: bool,
    code: &'a str,
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                code = self.code.as_str(),
                status = self.status.as_u16(),
                detail = ?self.detail,
                "server error"
            );
        } else {
            tracing::debug!(
                code = self.code.as_str(),
                status = self.status.as_u16(),
                "client error"
            );
        }

        let body = ErrorBody {
            ok: false,
            code: self.code.as_str(),
            error: self.message.as_ref(),
            detail: self.detail.as_deref(),
        };
        (self.status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::internal(err.to_string())
    }
}

/// Uniform success envelope. `data` flattens into the top-level object, so the
/// wire shape stays `{ok: true, code: "registered", handle: "...", did: "..."}`.
#[derive(Serialize)]
pub struct Success<T: Serialize> {
    pub ok: bool,
    pub code: &'static str,
    #[serde(flatten)]
    pub data: T,
}

impl<T: Serialize> Success<T> {
    pub fn new(code: Code, data: T) -> Self {
        Self {
            ok: true,
            code: code.as_str(),
            data,
        }
    }
}

pub fn success<T: Serialize>(code: Code, data: T) -> (StatusCode, Json<Success<T>>) {
    (code.status(), Json(Success::new(code, data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn error_body(err: &ApiError) -> serde_json::Value {
        serde_json::to_value(ErrorBody {
            ok: false,
            code: err.code.as_str(),
            error: err.message.as_ref(),
            detail: err.detail.as_deref(),
        })
        .unwrap()
    }

    #[test]
    fn error_body_shape_matches_contract() {
        let err = ApiError::new(Code::SubdomainTaken);
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(
            error_body(&err),
            json!({
                "ok": false,
                "code": "subdomain_taken",
                "error": "that handle is already claimed",
            })
        );
    }

    #[test]
    fn detail_appears_only_when_set() {
        let with = ApiError::new(Code::InternalError).with_detail("db unreachable");
        assert_eq!(error_body(&with)["detail"], "db unreachable");

        let without = ApiError::new(Code::InternalError);
        assert!(error_body(&without).get("detail").is_none());
    }

    #[test]
    fn success_envelope_flattens_payload() {
        let (status, json_body) = success(
            Code::Registered,
            json!({ "handle": "alice.goodgirls.onl", "did": "did:plc:abc" }),
        );
        assert_eq!(status, StatusCode::OK);
        let v = serde_json::to_value(&json_body.0).unwrap();
        assert_eq!(
            v,
            json!({
                "ok": true,
                "code": "registered",
                "handle": "alice.goodgirls.onl",
                "did": "did:plc:abc",
            })
        );
    }

    #[test]
    fn every_code_has_a_distinct_tag() {
        let all = [
            Code::Registered,
            Code::AdminRegistered,
            Code::Renamed,
            Code::Deleted,
            Code::Listed,
            Code::Wiped,
            Code::Exported,
            Code::LoggedIn,
            Code::BadJson,
            Code::MissingFields,
            Code::ConfirmRequired,
            Code::SubdomainTooShort,
            Code::SubdomainTooLong,
            Code::SubdomainInvalidChars,
            Code::SubdomainHyphenRules,
            Code::SubdomainReserved,
            Code::SubdomainBlocked,
            Code::SubdomainTaken,
            Code::DidHasHandle,
            Code::DidHasSecret,
            Code::HandleNotFound,
            Code::DidNotFound,
            Code::WrongKey,
            Code::Unauthorized,
            Code::CsrfInvalid,
            Code::SessionInvalid,
            Code::HandleResolveFailed,
            Code::BlueskyUnavailable,
            Code::BlueskyTimeout,
            Code::NotFound,
            Code::InternalError,
        ];
        let mut tags: Vec<&'static str> = all.iter().map(|c| c.as_str()).collect();
        tags.sort();
        let before = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), before, "duplicate code tags");
    }
}
