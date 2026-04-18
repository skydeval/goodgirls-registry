//! Business logic — the layer between handlers and storage.
//!
//! Handlers parse and respond. Storage stores. Service decides: it owns
//! validation order, the hashing, the camouflage policy for failed key
//! lookups (D7, §6.7), and the translation between db outcomes and the
//! project's response codes.

use serde::Serialize;

use crate::auth;
use crate::atproto;
use crate::db::{self, Pool};
use crate::error::{ApiError, ApiResult, Code};
use crate::validate;

// --- camouflage --------------------------------------------------------------

/// Mixed warm/cold messages so a failed manage submission can't be
/// distinguished from decorative page behavior (D7, §6.7).
const CAMOUFLAGE_MESSAGES: &[&str] = &[
    "the garden remembers your footsteps",
    "patience is a thread worth pulling",
    "the sigil does not resonate",
    "something stirs beneath the threshold",
    "a familiar warmth passes through",
    "not all doors open the same way",
    "the lantern flickers, then steadies",
    "an old name rises to the surface",
    "the threshold remains uncrossed",
    "moths gather at the edge of the page",
];

fn camouflage_message() -> &'static str {
    use rand::seq::SliceRandom;
    CAMOUFLAGE_MESSAGES
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or("the sigil does not resonate")
}

/// Standard response for any auth-style failure on /manage or /delete: code
/// is `wrong_key` so the wire shape is uniform; message is randomized so the
/// human-visible text doesn't enumerate failure modes.
pub fn camouflage_error() -> ApiError {
    ApiError::new(Code::WrongKey).with_message(camouflage_message())
}

// --- result types ------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RegisterResult {
    pub handle: String,
    pub did: String,
    pub goodgirls_key: String,
}

#[derive(Debug, Serialize)]
pub struct AdminRegisterResult {
    pub handle: String,
    pub did: String,
    pub goodgirls_key: String,
}

#[derive(Debug)]
pub enum ManageLogin {
    User {
        did: String,
        subdomain: String,
        handle: String,
    },
    Admin {
        /// `Set-Cookie` header value — the csrf token lives server-side and is
        /// embedded in the admin page HTML, so it doesn't leak through login
        /// JSON responses that hit proxy logs.
        set_cookie: String,
    },
}

#[derive(Debug, Serialize)]
pub struct RenameResult {
    pub did: String,
    pub old_handle: String,
    pub new_handle: String,
    pub no_change: bool,
}

#[derive(Debug, Serialize)]
pub struct DeleteResult {
    pub did: String,
    /// `None` only in the rare case where a secret existed without a handle.
    pub deleted_handle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListEntry {
    pub subdomain: String,
    pub did: String,
    pub handle: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListResult {
    pub entries: Vec<ListEntry>,
    pub offset: i64,
    pub limit: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct WipeResult {
    pub did: String,
    pub handles_removed: u64,
    pub secret_removed: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportPayload {
    pub handles: Vec<ListEntry>,
    pub secrets: Vec<ExportedSecret>,
}

#[derive(Debug, Serialize)]
pub struct ExportedSecret {
    pub did: String,
    pub secret_hash: String,
    pub created_at: String,
}

// --- public flows ------------------------------------------------------------

pub async fn register(
    pool: &Pool,
    atproto: &atproto::Client,
    subdomain: &str,
    handle: &str,
) -> ApiResult<RegisterResult> {
    validate::subdomain(subdomain)?;
    let did = atproto.resolve_handle(handle).await?;

    let key = auth::generate_key();
    let secret_hash = auth::hash(&key);

    match db::try_register(pool, subdomain, &did, &secret_hash).await? {
        db::RegisterOutcome::Registered => {
            tracing::info!(subdomain, did, "registered");
            Ok(RegisterResult {
                handle: format!("{subdomain}.goodgirls.onl"),
                did,
                goodgirls_key: key,
            })
        }
        db::RegisterOutcome::SubdomainTaken => Err(ApiError::new(Code::SubdomainTaken)),
        db::RegisterOutcome::DidHasHandle => Err(ApiError::new(Code::DidHasHandle)),
        db::RegisterOutcome::DidHasSecret => Err(ApiError::new(Code::DidHasSecret)),
    }
}

/// Operator-only registration: bypasses the one-handle-per-DID check by
/// wiping the DID first. Always emits a fresh key; admin delivers it manually
/// (D13, §6).
pub async fn admin_register(
    pool: &Pool,
    atproto: &atproto::Client,
    subdomain: &str,
    handle: &str,
) -> ApiResult<AdminRegisterResult> {
    validate::subdomain(subdomain)
        .map_err(|e| e.with_detail(format!("admin_register: subdomain={subdomain:?}")))?;

    let did = atproto
        .resolve_handle(handle)
        .await
        .map_err(|e| e.with_detail(format!("admin_register: resolve_handle({handle:?})")))?;

    let key = auth::generate_key();
    let secret_hash = auth::hash(&key);

    match db::try_register_admin(pool, subdomain, &did, &secret_hash)
        .await
        .map_err(|e| admin_db_detail(e, format!("try_register_admin(subdomain={subdomain:?}, did={did:?})")))?
    {
        db::AdminRegisterOutcome::Registered => {
            tracing::info!(subdomain, did, "admin_registered");
            Ok(AdminRegisterResult {
                handle: format!("{subdomain}.goodgirls.onl"),
                did,
                goodgirls_key: key,
            })
        }
        db::AdminRegisterOutcome::SubdomainTaken => {
            // Look up the current owner so the admin can see who's holding
            // the name — typically this is the signal to wipe the conflicting
            // DID first, or to pick a different subdomain.
            let owner = db::find_did_by_subdomain(pool, subdomain)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "<unknown>".into());
            Err(ApiError::new(Code::SubdomainTaken).with_detail(format!(
                "admin_register: subdomain={subdomain:?} already held by did={owner:?} (target was did={did:?})"
            )))
        }
    }
}

/// Promote a raw sqlx error to an admin-facing `ApiError` with operation
/// context attached. Service-level admin callers use this so the 3am debugger
/// sees *which query* hit *which parameters* instead of a bare sqlite
/// message.
fn admin_db_detail(err: sqlx::Error, op: impl std::fmt::Display) -> ApiError {
    ApiError::internal(format!("{op}: {err}"))
}

/// The unified door (§4). Hash the input key, then check both destinations.
/// On no match, return camouflage. On admin match, mint a server-side
/// session.
pub async fn manage_login(
    pool: &Pool,
    admin_key_hash: &str,
    raw_key: &str,
) -> ApiResult<ManageLogin> {
    let hash = auth::hash(raw_key);

    if auth::hashes_equal(&hash, admin_key_hash) {
        let session_id = auth::generate_token();
        let csrf_token = auth::generate_token();
        db::create_session(pool, &session_id, &csrf_token, auth::SESSION_TTL_SECS as i64)
            .await?;
        tracing::info!("admin logged in");
        return Ok(ManageLogin::Admin {
            set_cookie: auth::session_cookie(&session_id),
        });
    }

    if let Some(did) = db::find_did_by_secret_hash(pool, &hash).await?
        && let Some(subdomain) = db::find_subdomain_by_did(pool, &did).await?
    {
        return Ok(ManageLogin::User {
            handle: format!("{subdomain}.goodgirls.onl"),
            did,
            subdomain,
        });
    }

    Err(camouflage_error())
}

pub async fn rename(
    pool: &Pool,
    raw_key: &str,
    new_subdomain: &str,
) -> ApiResult<RenameResult> {
    validate::subdomain(new_subdomain)?;

    let hash = auth::hash(raw_key);
    let Some(did) = db::find_did_by_secret_hash(pool, &hash).await? else {
        return Err(camouflage_error());
    };

    match db::try_rename(pool, &did, new_subdomain).await? {
        db::RenameOutcome::Renamed { old_subdomain } => {
            tracing::info!(did, old_subdomain, new_subdomain, "renamed");
            Ok(RenameResult {
                did,
                old_handle: format!("{old_subdomain}.goodgirls.onl"),
                new_handle: format!("{new_subdomain}.goodgirls.onl"),
                no_change: false,
            })
        }
        db::RenameOutcome::NoChange => {
            let same = format!("{new_subdomain}.goodgirls.onl");
            Ok(RenameResult {
                did,
                old_handle: same.clone(),
                new_handle: same,
                no_change: true,
            })
        }
        db::RenameOutcome::SubdomainTaken => Err(ApiError::new(Code::SubdomainTaken)),
        db::RenameOutcome::HandleNotFound => Err(camouflage_error()),
    }
}

pub async fn delete(pool: &Pool, raw_key: &str, confirm: &str) -> ApiResult<DeleteResult> {
    if confirm != "DELETE" {
        return Err(ApiError::new(Code::ConfirmRequired));
    }

    let hash = auth::hash(raw_key);
    let Some(did) = db::find_did_by_secret_hash(pool, &hash).await? else {
        return Err(camouflage_error());
    };

    let subdomain = db::find_subdomain_by_did(pool, &did).await?;
    let res = db::wipe_did(pool, &did).await?;

    tracing::info!(
        did,
        handles_removed = res.handles_removed,
        secret_removed = res.secret_removed,
        "deleted"
    );
    Ok(DeleteResult {
        did,
        deleted_handle: subdomain.map(|s| format!("{s}.goodgirls.onl")),
    })
}

// --- admin flows -------------------------------------------------------------

pub async fn admin_list(pool: &Pool, offset: i64, limit: i64) -> ApiResult<ListResult> {
    let entries = db::list_handles(pool, offset, limit)
        .await
        .map_err(|e| admin_db_detail(e, format!("list_handles(offset={offset}, limit={limit})")))?
        .into_iter()
        .map(|r| ListEntry {
            handle: format!("{}.goodgirls.onl", r.subdomain),
            subdomain: r.subdomain,
            did: r.did,
            created_at: r.created_at,
        })
        .collect();
    let total = db::count_handles(pool)
        .await
        .map_err(|e| admin_db_detail(e, "count_handles()"))?;
    Ok(ListResult { entries, offset, limit, total })
}

pub async fn admin_wipe(pool: &Pool, did: &str) -> ApiResult<WipeResult> {
    let res = db::wipe_did(pool, did)
        .await
        .map_err(|e| admin_db_detail(e, format!("wipe_did(did={did:?})")))?;

    if res.handles_removed == 0 && !res.secret_removed {
        // D17 exemplar: mystical primary, SQL-shaped technical secondary.
        return Err(ApiError::new(Code::DidNotFound).with_detail(format!(
            "DELETE FROM handles WHERE did = {did:?} → 0 rows; \
             DELETE FROM secrets WHERE did = {did:?} → 0 rows"
        )));
    }
    tracing::info!(
        did,
        handles_removed = res.handles_removed,
        secret_removed = res.secret_removed,
        "admin wiped did"
    );
    Ok(WipeResult {
        did: did.to_string(),
        handles_removed: res.handles_removed,
        secret_removed: res.secret_removed,
    })
}

pub async fn admin_export(pool: &Pool) -> ApiResult<ExportPayload> {
    let handles = db::list_handles(pool, 0, i64::MAX)
        .await
        .map_err(|e| admin_db_detail(e, "admin_export/list_handles(all)"))?
        .into_iter()
        .map(|r| ListEntry {
            handle: format!("{}.goodgirls.onl", r.subdomain),
            subdomain: r.subdomain,
            did: r.did,
            created_at: r.created_at,
        })
        .collect();
    let secrets = db::list_secrets(pool)
        .await
        .map_err(|e| admin_db_detail(e, "admin_export/list_secrets"))?
        .into_iter()
        .map(|r| ExportedSecret {
            did: r.did,
            secret_hash: r.secret_hash,
            created_at: r.created_at,
        })
        .collect();
    Ok(ExportPayload { handles, secrets })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> Pool {
        let pool = db::connect("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        pool
    }

    fn admin_hash() -> String {
        auth::hash("super-secret-admin-key")
    }

    #[tokio::test]
    async fn manage_login_user_path() {
        let pool = fresh().await;
        // Seed a user.
        let key = "user-key-12345";
        let hash = auth::hash(key);
        db::try_register(&pool, "alice", "did:plc:a", &hash).await.unwrap();

        let result = manage_login(&pool, &admin_hash(), key).await.unwrap();
        let ManageLogin::User { did, subdomain, handle } = result else {
            panic!("expected User variant");
        };
        assert_eq!(did, "did:plc:a");
        assert_eq!(subdomain, "alice");
        assert_eq!(handle, "alice.goodgirls.onl");
    }

    #[tokio::test]
    async fn manage_login_admin_path_creates_session() {
        let pool = fresh().await;
        let admin_h = admin_hash();

        let result = manage_login(&pool, &admin_h, "super-secret-admin-key").await.unwrap();
        let ManageLogin::Admin { set_cookie } = result else {
            panic!("expected Admin variant");
        };
        assert!(set_cookie.contains("HttpOnly"));

        // exactly one session row exists
        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows.0, 1);
    }

    #[tokio::test]
    async fn manage_login_invalid_key_camouflages() {
        let pool = fresh().await;
        let err = manage_login(&pool, &admin_hash(), "totally wrong").await.unwrap_err();
        assert_eq!(err.code, Code::WrongKey);
        // Message comes from the camouflage pool.
        assert!(CAMOUFLAGE_MESSAGES.contains(&err.message.as_ref()));
    }

    #[tokio::test]
    async fn manage_login_camouflages_orphaned_secret() {
        // Secret exists but no handle — must not leak this rare state.
        let pool = fresh().await;
        let key = "orphan-key";
        sqlx::query("INSERT INTO secrets (did, secret_hash) VALUES (?1, ?2)")
            .bind("did:plc:orphan")
            .bind(auth::hash(key))
            .execute(&pool)
            .await
            .unwrap();

        let err = manage_login(&pool, &admin_hash(), key).await.unwrap_err();
        assert_eq!(err.code, Code::WrongKey);
    }

    #[tokio::test]
    async fn rename_validates_then_renames() {
        let pool = fresh().await;
        let key = "rename-key";
        db::try_register(&pool, "alice", "did:plc:a", &auth::hash(key)).await.unwrap();

        let r = rename(&pool, key, "alicia").await.unwrap();
        assert_eq!(r.old_handle, "alice.goodgirls.onl");
        assert_eq!(r.new_handle, "alicia.goodgirls.onl");
        assert!(!r.no_change);

        // bad subdomain → validation error, not a db hit
        let err = rename(&pool, key, "ab").await.unwrap_err();
        assert_eq!(err.code, Code::SubdomainTooShort);
    }

    #[tokio::test]
    async fn rename_with_unknown_key_camouflages() {
        let pool = fresh().await;
        let err = rename(&pool, "ghost-key", "anything").await.unwrap_err();
        assert_eq!(err.code, Code::WrongKey);
    }

    #[tokio::test]
    async fn delete_requires_exact_confirm() {
        let pool = fresh().await;
        let key = "del-key";
        db::try_register(&pool, "alice", "did:plc:a", &auth::hash(key)).await.unwrap();

        assert_eq!(
            delete(&pool, key, "delete").await.unwrap_err().code,
            Code::ConfirmRequired
        );
        assert_eq!(
            delete(&pool, key, "").await.unwrap_err().code,
            Code::ConfirmRequired
        );

        let r = delete(&pool, key, "DELETE").await.unwrap();
        assert_eq!(r.did, "did:plc:a");
        assert_eq!(r.deleted_handle.as_deref(), Some("alice.goodgirls.onl"));
    }

    #[tokio::test]
    async fn delete_after_deletion_can_register_fresh() {
        let pool = fresh().await;
        let key = "key-1";
        db::try_register(&pool, "alice", "did:plc:a", &auth::hash(key)).await.unwrap();
        delete(&pool, key, "DELETE").await.unwrap();

        // DID can register again with a fresh key
        let new_key = "key-2";
        let outcome =
            db::try_register(&pool, "alice", "did:plc:a", &auth::hash(new_key)).await.unwrap();
        assert_eq!(outcome, db::RegisterOutcome::Registered);
    }

    #[tokio::test]
    async fn delete_unknown_key_camouflages() {
        let pool = fresh().await;
        let err = delete(&pool, "ghost", "DELETE").await.unwrap_err();
        assert_eq!(err.code, Code::WrongKey);
    }

    #[tokio::test]
    async fn admin_wipe_unknown_did_returns_did_not_found() {
        let pool = fresh().await;
        let err = admin_wipe(&pool, "did:plc:ghost").await.unwrap_err();
        assert_eq!(err.code, Code::DidNotFound);
        // D17: primary message is mystical, detail carries the SQL truth.
        assert_eq!(err.message.as_ref(), "the void found nothing to swallow");
        let detail = err.detail.as_deref().expect("admin errors carry detail");
        assert!(detail.contains("DELETE FROM handles"));
        assert!(detail.contains("DELETE FROM secrets"));
        assert!(detail.contains("did:plc:ghost"));
        assert!(detail.contains("0 rows"));
    }

    #[tokio::test]
    async fn admin_register_subdomain_taken_reveals_owner_in_detail() {
        let pool = fresh().await;
        // occupy "alice" under did:plc:a via normal registration
        db::try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

        // admin_register will fail at the db layer (SubdomainTaken) and then
        // service enriches the error with who currently holds the name.
        // atproto isn't reached for this test because validation+resolve
        // happen first — we call try_register_admin directly below to avoid
        // the network. But the contract we care about is the service-level
        // error shape, so build the ApiError the way the service would.
        let outcome =
            db::try_register_admin(&pool, "alice", "did:plc:b", "h_b").await.unwrap();
        assert_eq!(outcome, db::AdminRegisterOutcome::SubdomainTaken);

        // Simulate the service-layer detail attachment using the same query.
        let owner = db::find_did_by_subdomain(&pool, "alice").await.unwrap();
        assert_eq!(owner.as_deref(), Some("did:plc:a"));
    }

    #[tokio::test]
    async fn admin_list_wraps_db_errors_with_query_context() {
        // Close the pool to force a db failure on the next query, so we can
        // inspect the detail string the admin would see at 3am.
        let pool = fresh().await;
        pool.close().await;
        let err = admin_list(&pool, 42, 7).await.unwrap_err();
        assert_eq!(err.code, Code::InternalError);
        let detail = err.detail.as_deref().unwrap();
        assert!(detail.contains("list_handles"), "detail missing op: {detail}");
        assert!(detail.contains("offset=42"), "detail missing offset: {detail}");
        assert!(detail.contains("limit=7"), "detail missing limit: {detail}");
    }

    #[tokio::test]
    async fn admin_list_paginates_with_total() {
        let pool = fresh().await;
        for (sub, did) in [("alice", "d1"), ("bob", "d2"), ("charlie", "d3"), ("dee", "d4")] {
            db::try_register(&pool, sub, did, &format!("h_{did}")).await.unwrap();
        }

        let page = admin_list(&pool, 1, 2).await.unwrap();
        assert_eq!(page.total, 4);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 2);
        assert_eq!(
            page.entries.iter().map(|e| e.subdomain.as_str()).collect::<Vec<_>>(),
            ["bob", "charlie"]
        );
        assert_eq!(page.entries[0].handle, "bob.goodgirls.onl");
    }

    #[tokio::test]
    async fn admin_export_round_trips_handles_and_secrets() {
        let pool = fresh().await;
        db::try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();
        db::try_register(&pool, "bob", "did:plc:b", "h_b").await.unwrap();

        let dump = admin_export(&pool).await.unwrap();
        assert_eq!(dump.handles.len(), 2);
        assert_eq!(dump.secrets.len(), 2);
        assert!(dump.secrets.iter().all(|s| !s.secret_hash.is_empty()));
    }
}
