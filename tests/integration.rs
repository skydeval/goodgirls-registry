//! End-to-end routing tests. Bluesky-dependent paths (register, admin
//! register) are covered by service-level unit tests; here we exercise the
//! HTTP surface: routing, auth gates, response shapes, subdomain routing.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use goodgirls_registry::{
    atproto,
    auth,
    db,
    routes,
    state::AppState,
};

async fn app() -> (axum::Router, db::Pool) {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let state = AppState {
        pool: pool.clone(),
        atproto: atproto::Client::new().unwrap(),
        admin_key_hash: auth::hash("test-admin-key"),
        base_domain: "goodgirls.onl".into(),
        decoy_path: "/gg".into(),
    };
    (routes::build(state), pool)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn post(path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "goodgirls.onl")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(path: &str, host: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn index_page_served_on_apex() {
    let (app, _) = app().await;
    let resp = app.oneshot(get("/", "goodgirls.onl")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert!(bytes.starts_with(b"<!doctype html>"));
}

#[tokio::test]
async fn well_known_returns_did_for_known_subdomain() {
    let (app, pool) = app().await;
    db::try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

    let resp = app
        .oneshot(get("/.well-known/atproto-did", "alice.goodgirls.onl"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&bytes[..], b"did:plc:a");
}

#[tokio::test]
async fn well_known_404_for_unknown_subdomain() {
    let (app, _) = app().await;
    let resp = app
        .oneshot(get("/.well-known/atproto-did", "nobody.goodgirls.onl"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn well_known_400_on_apex() {
    let (app, _) = app().await;
    let resp = app
        .oneshot(get("/.well-known/atproto-did", "goodgirls.onl"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn manage_login_user_path_returns_handle() {
    let (app, pool) = app().await;
    db::try_register(&pool, "alice", "did:plc:a", &auth::hash("user-key-1")).await.unwrap();

    let resp = app
        .oneshot(post("/manage", json!({ "key": "user-key-1" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["role"], "user");
    assert_eq!(body["handle"], "alice.goodgirls.onl");
    assert_eq!(body["did"], "did:plc:a");
}

#[tokio::test]
async fn manage_login_admin_sets_cookie_and_redirect() {
    let (app, _) = app().await;
    let resp = app
        .oneshot(post("/manage", json!({ "key": "test-admin-key" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Secure"));

    let body = body_json(resp).await;
    assert_eq!(body["role"], "admin");
    assert_eq!(body["redirect"], "/admin");
}

#[tokio::test]
async fn manage_login_wrong_key_camouflages_uniformly() {
    let (app, _) = app().await;
    let resp = app
        .oneshot(post("/manage", json!({ "key": "totally wrong" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "wrong_key");
}

#[tokio::test]
async fn admin_endpoints_require_session() {
    let (app, _) = app().await;
    let resp = app
        .oneshot(post("/api/admin/list", json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "session_invalid");
}

#[tokio::test]
async fn admin_list_with_valid_session_and_csrf_succeeds() {
    let (app, pool) = app().await;
    db::try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

    // Plant a session directly rather than going through login, so the
    // cookie/csrf values are known to the test.
    let session_id = "sess_test_abcdef";
    let csrf = "csrf_test_xyz";
    db::create_session(&pool, session_id, csrf, 3600).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/admin/list")
        .header(header::HOST, "goodgirls.onl")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{}={session_id}", auth::SESSION_COOKIE_NAME))
        .header(auth::CSRF_HEADER_NAME, csrf)
        .body(Body::from(json!({"offset": 0, "limit": 10}).to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["code"], "listed");
    assert_eq!(body["total"], 1);
    assert_eq!(body["entries"][0]["handle"], "alice.goodgirls.onl");
}

#[tokio::test]
async fn admin_with_wrong_csrf_is_rejected() {
    let (app, pool) = app().await;
    db::create_session(&pool, "sess", "real-csrf", 3600).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/admin/list")
        .header(header::HOST, "goodgirls.onl")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{}=sess", auth::SESSION_COOKIE_NAME))
        .header(auth::CSRF_HEADER_NAME, "wrong-csrf")
        .body(Body::from(json!({}).to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "csrf_invalid");
}

#[tokio::test]
async fn delete_requires_exact_confirm_string() {
    let (app, pool) = app().await;
    db::try_register(&pool, "alice", "did:plc:a", &auth::hash("key-del")).await.unwrap();

    let resp = app
        .clone()
        .oneshot(post("/delete", json!({ "key": "key-del", "confirm": "delete" })))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["code"], "confirm_required");

    let resp = app
        .oneshot(post("/delete", json!({ "key": "key-del", "confirm": "DELETE" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "deleted");
    assert_eq!(body["deleted_handle"], "alice.goodgirls.onl");
}

#[tokio::test]
async fn decoy_returns_page_then_mystical_on_post() {
    let (app, _) = app().await;

    let resp = app.clone().oneshot(get("/gg", "goodgirls.onl")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert!(bytes.starts_with(b"<!doctype html>"));

    let resp = app
        .oneshot(post("/gg", json!({ "key": "literally anything" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "wrong_key");
}

#[tokio::test]
async fn bad_json_is_diagnosed() {
    let (app, _) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/manage")
        .header(header::HOST, "goodgirls.onl")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("not json at all"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["code"], "bad_json");
}
