//! Manage flow + admin endpoints.
//!
//! /manage is the key-first unified door: one input field, three
//! destinations (user session, admin session, mystical camouflage). Admin
//! endpoints under /api/admin/* sit behind session + CSRF (D8).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::auth;
use crate::error::{ApiError, ApiResult, Code, success};
use crate::handlers::{cookie_value, parse_json, require_admin_session};
use crate::service::{self, ManageLogin};
use crate::state::AppState;

const MANAGE_HTML: &str = include_str!("../../templates/manage.html");
const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

// --- pages ------------------------------------------------------------------

pub async fn manage_page() -> Html<&'static str> {
    Html(MANAGE_HTML)
}

/// The admin console page, gated by session cookie. On invalid/expired
/// session we redirect back to /manage rather than showing a bare error —
/// the operator's first instinct on a blank screen is to re-login.
pub async fn admin_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_id) = cookie_value(&headers, auth::SESSION_COOKIE_NAME) else {
        return redirect_to_manage();
    };

    let session = match crate::db::find_active_session(&state.pool, session_id).await {
        Ok(Some(s)) => s,
        _ => return redirect_to_manage(),
    };

    let html = ADMIN_HTML
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{csrf_token}}", &session.csrf_token);
    Html(html).into_response()
}

fn redirect_to_manage() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/manage")]).into_response()
}

// --- POST /manage -----------------------------------------------------------

#[derive(Deserialize)]
struct ManagePost {
    #[serde(default)]
    key: String,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    subdomain: Option<String>,
}

pub async fn manage_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let req: ManagePost = parse_json(&body)?;
    let key = req.key.trim();
    if key.is_empty() {
        // For consistent camouflage, an empty key is treated as a bad key,
        // not as a missing field. Probers can't distinguish either way.
        return Err(service::camouflage_error());
    }

    match req.action.as_deref() {
        None | Some("") | Some("login") => login(&state, &headers, key).await,
        Some("rename") => {
            let new_sub = req
                .subdomain
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if new_sub.is_empty() {
                return Err(ApiError::new(Code::MissingFields));
            }
            let result = service::rename(&state.pool, key, &new_sub).await?;
            Ok(success(Code::Renamed, result).into_response())
        }
        Some(other) => Err(ApiError::new(Code::MissingFields)
            .with_message(format!("unknown action: {other}"))),
    }
}

async fn login(state: &AppState, _headers: &HeaderMap, key: &str) -> ApiResult<Response> {
    let login = service::manage_login(&state.pool, &state.admin_key_hash, key).await?;

    match login {
        ManageLogin::User { did, subdomain, handle } => {
            let body = serde_json::json!({
                "ok": true,
                "code": "logged_in",
                "role": "user",
                "did": did,
                "subdomain": subdomain,
                "handle": handle,
            });
            Ok((StatusCode::OK, Json(body)).into_response())
        }
        ManageLogin::Admin { set_cookie } => {
            let body = serde_json::json!({
                "ok": true,
                "code": "logged_in",
                "role": "admin",
                "redirect": "/admin",
            });
            let mut resp = (StatusCode::OK, Json(body)).into_response();
            resp.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&set_cookie).expect("session cookie is ASCII"),
            );
            Ok(resp)
        }
    }
}

// --- POST /delete -----------------------------------------------------------

#[derive(Deserialize)]
struct DeletePost {
    #[serde(default)]
    key: String,
    #[serde(default)]
    confirm: String,
}

pub async fn delete_post(
    State(state): State<AppState>,
    body: Bytes,
) -> ApiResult<Response> {
    let req: DeletePost = parse_json(&body)?;
    let key = req.key.trim();
    let confirm = req.confirm.trim();
    let result = service::delete(&state.pool, key, confirm).await?;
    Ok(success(Code::Deleted, result).into_response())
}

// --- POST /api/admin/list ---------------------------------------------------

#[derive(Deserialize)]
struct ListPost {
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

pub async fn admin_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    require_admin_session(&state, &headers).await?;
    let req: ListPost = parse_json(&body)?;
    let offset = req.offset.unwrap_or(0).max(0);
    let limit = req.limit.unwrap_or(100).clamp(1, 500);
    let result = service::admin_list(&state.pool, offset, limit).await?;
    Ok(success(Code::Listed, result).into_response())
}

// --- POST /api/admin/wipe-did ----------------------------------------------

#[derive(Deserialize)]
struct WipePost {
    #[serde(default)]
    did: String,
}

pub async fn admin_wipe(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    require_admin_session(&state, &headers).await?;
    let req: WipePost = parse_json(&body)?;
    let did = req.did.trim();
    if did.is_empty() {
        return Err(ApiError::new(Code::MissingFields));
    }
    let result = service::admin_wipe(&state.pool, did).await?;
    Ok(success(Code::Wiped, result).into_response())
}

// --- POST /api/admin/export ------------------------------------------------

pub async fn admin_export(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    require_admin_session(&state, &headers).await?;
    let payload = service::admin_export(&state.pool).await?;
    Ok(success(Code::Exported, payload).into_response())
}
