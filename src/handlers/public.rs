//! Public-facing handlers: index page, register, well-known, decoy.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::auth;
use crate::db;
use crate::error::{ApiError, ApiResult, Code, Success, success};
use crate::handlers::{host_subdomain, parse_json};
use crate::service;
use crate::state::AppState;

const INDEX_HTML: &str = include_str!("../../templates/index.html");

pub async fn index_page() -> Html<&'static str> {
    Html(INDEX_HTML)
}

// --- register ---------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    subdomain: String,
    #[serde(default)]
    handle: String,
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let req: RegisterRequest = parse_json(&body)?;
    let subdomain = req.subdomain.trim().to_lowercase();
    let handle = req.handle.trim().to_string();
    if subdomain.is_empty() || handle.is_empty() {
        return Err(ApiError::new(Code::MissingFields));
    }

    if is_admin_token(&headers, &state.admin_key_hash) {
        let result = service::admin_register(&state.pool, &state.atproto, &subdomain, &handle).await?;
        Ok(success(Code::AdminRegistered, result).into_response())
    } else {
        let result = service::register(&state.pool, &state.atproto, &subdomain, &handle).await?;
        Ok(success(Code::Registered, result).into_response())
    }
}

/// §4: `x-goodgirls-token` header authenticates admin register. The admin
/// delivers their raw key in the header; we hash and compare against the
/// stored hash. Same admin secret as the console login.
fn is_admin_token(headers: &HeaderMap, admin_key_hash: &str) -> bool {
    let raw = match headers.get("x-goodgirls-token").and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return false,
    };
    auth::hashes_equal(&auth::hash(raw), admin_key_hash)
}

// --- well-known -------------------------------------------------------------

/// `GET /.well-known/atproto-did` — only valid on subdomain hosts. Returns
/// the mapped DID as plain text, which is what AT Protocol expects.
pub async fn well_known(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let Some(sub) = host_subdomain(host, &state.base_domain) else {
        return (StatusCode::BAD_REQUEST, "no subdomain").into_response();
    };

    match db::find_did_by_subdomain(&state.pool, sub).await {
        Ok(Some(did)) => (StatusCode::OK, did).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            tracing::error!(subdomain = sub, err = %e, "well-known db error");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

// --- decoy ------------------------------------------------------------------

const DECOY_HTML: &str = r#"<!doctype html>
<html><head>
<meta charset="utf-8"/>
<title>sigil gate</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root{--bg:#151515;--text:#eee;--border:#444;--purple:#a060ff;}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;}
main{width:100%;max-width:360px;text-align:center;}
h1{font-size:1.1rem;color:var(--purple);}
form{margin-top:1rem;}
input{width:100%;padding:0.5rem;border-radius:6px;background:#1f1f1f;border:1px solid var(--border);color:#ccc;box-sizing:border-box;}
button{margin-top:1rem;width:100%;padding:0.55rem;background:#3a3a3a;border:none;border-radius:6px;color:#eee;font-weight:600;cursor:pointer;}
#msg{margin-top:1rem;font-size:0.85rem;color:#aaa;min-height:1.2em;}
</style></head>
<body><main>
<h1>sigil gate</h1>
<form id="f"><input id="k" type="password" placeholder="sigil" autocomplete="off"/><button>attune</button></form>
<div id="msg"></div>
<script>
const f=document.getElementById("f"),m=document.getElementById("msg");
f.addEventListener("submit",async e=>{e.preventDefault();
const r=await fetch(location.pathname,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:document.getElementById("k").value})});
const d=await r.json().catch(()=>({})); m.textContent=d.error||"the gate is quiet";});
</script>
</main></body></html>"#;

pub async fn decoy_get(headers: HeaderMap) -> Html<&'static str> {
    log_decoy_poke(&headers, "GET");
    Html(DECOY_HTML)
}

pub async fn decoy_post(headers: HeaderMap, _body: Bytes) -> Response {
    log_decoy_poke(&headers, "POST");

    let body = Success {
        ok: false,
        code: "wrong_key",
        data: serde_json::json!({ "error": service::camouflage_error().message.to_string() }),
    };
    // Always 401 so it looks like a real gate.
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

/// D6: every decoy interaction is logged for operator awareness. `tracing`
/// stamps each event with a timestamp via the subscriber in `main`, so this
/// function just supplies the context fields. Real IP comes from Cloudflare
/// (`CF-Connecting-IP`) with `X-Forwarded-For` as a fallback for anyone
/// hitting the origin directly during debugging.
fn log_decoy_poke(headers: &HeaderMap, method: &str) {
    let ip = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?");
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?");
    tracing::warn!(ip, method, user_agent, "decoy poked");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_token_matches_hash() {
        let hash = auth::hash("operator-key");
        let mut h = HeaderMap::new();
        h.insert("x-goodgirls-token", "operator-key".parse().unwrap());
        assert!(is_admin_token(&h, &hash));

        h.insert("x-goodgirls-token", "wrong".parse().unwrap());
        assert!(!is_admin_token(&h, &hash));

        assert!(!is_admin_token(&HeaderMap::new(), &hash));
    }
}
