//! SQLite access layer. Owns the pool, the embedded migrations, and every
//! query the service runs.
//!
//! Multi-step writes use `BEGIN IMMEDIATE` so two racing registrations for
//! the same DID serialize instead of producing half-written state (D7, §6.12).
//! Single-row reads and deletes go straight against the pool — no transaction
//! needed.

use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::SqlitePool;

pub type Pool = SqlitePool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect(url: &str) -> Result<Pool, sqlx::Error> {
    // WAL + NORMAL synchronous is the canonical "server sqlite" profile:
    // concurrent readers, one writer at a time, fsync on checkpoint not on
    // every commit. `busy_timeout` gives writers 5s to wait out contention
    // instead of failing immediately with SQLITE_BUSY.
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
}

pub async fn migrate(pool: &Pool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

// --- handles -----------------------------------------------------------------

pub async fn find_did_by_subdomain(pool: &Pool, subdomain: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT did FROM handles WHERE subdomain = ?1")
            .bind(subdomain)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(did,)| did))
}

pub async fn find_subdomain_by_did(pool: &Pool, did: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT subdomain FROM handles WHERE did = ?1")
            .bind(did)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(sub,)| sub))
}

pub async fn count_handles(pool: &Pool) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM handles")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

#[derive(Debug, Clone)]
pub struct HandleRow {
    pub subdomain: String,
    pub did: String,
    pub created_at: String,
}

pub async fn list_handles(pool: &Pool, offset: i64, limit: i64) -> Result<Vec<HandleRow>, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT subdomain, did, created_at FROM handles ORDER BY subdomain LIMIT ?1 OFFSET ?2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(subdomain, did, created_at)| HandleRow { subdomain, did, created_at })
        .collect())
}

// --- secrets -----------------------------------------------------------------

pub async fn find_did_by_secret_hash(
    pool: &Pool,
    secret_hash: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT did FROM secrets WHERE secret_hash = ?1")
            .bind(secret_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(did,)| did))
}

#[derive(Debug, Clone)]
pub struct SecretRow {
    pub did: String,
    pub secret_hash: String,
    pub created_at: String,
}

pub async fn list_secrets(pool: &Pool) -> Result<Vec<SecretRow>, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT did, secret_hash, created_at FROM secrets ORDER BY did",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(did, secret_hash, created_at)| SecretRow { did, secret_hash, created_at })
        .collect())
}

// --- atomic writes -----------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    Registered,
    SubdomainTaken,
    DidHasHandle,
    DidHasSecret,
}

/// User registration: three preconditions (subdomain free, DID has no handle,
/// DID has no secret) plus two inserts, all under a single `BEGIN IMMEDIATE`
/// so concurrent requests can't both "see free" and both write (D7, §6.12).
pub async fn try_register(
    pool: &Pool,
    subdomain: &str,
    did: &str,
    secret_hash: &str,
) -> Result<RegisterOutcome, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<RegisterOutcome, sqlx::Error> = async {
        if sqlx::query("SELECT 1 FROM handles WHERE subdomain = ?1")
            .bind(subdomain)
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
        {
            return Ok(RegisterOutcome::SubdomainTaken);
        }
        if sqlx::query("SELECT 1 FROM handles WHERE did = ?1")
            .bind(did)
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
        {
            return Ok(RegisterOutcome::DidHasHandle);
        }
        if sqlx::query("SELECT 1 FROM secrets WHERE did = ?1")
            .bind(did)
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
        {
            return Ok(RegisterOutcome::DidHasSecret);
        }

        sqlx::query("INSERT INTO secrets (did, secret_hash) VALUES (?1, ?2)")
            .bind(did)
            .bind(secret_hash)
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO handles (subdomain, did) VALUES (?1, ?2)")
            .bind(subdomain)
            .bind(did)
            .execute(&mut *conn)
            .await?;

        Ok(RegisterOutcome::Registered)
    }
    .await;

    finish_tx(&mut conn, result).await
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdminRegisterOutcome {
    Registered,
    /// The subdomain is held by a *different* DID — admin does not steal.
    SubdomainTaken,
}

/// Admin registration (D13, §4): skip the one-handle-per-DID check by first
/// wiping the DID's existing rows, then inserting fresh. Semantics are
/// "nuke-and-restart this DID with this subdomain and a new key." The only
/// refusal is if the chosen subdomain already belongs to a different DID —
/// admin does not take names from other users.
pub async fn try_register_admin(
    pool: &Pool,
    subdomain: &str,
    did: &str,
    secret_hash: &str,
) -> Result<AdminRegisterOutcome, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<AdminRegisterOutcome, sqlx::Error> = async {
        let owner: Option<(String,)> =
            sqlx::query_as("SELECT did FROM handles WHERE subdomain = ?1")
                .bind(subdomain)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some((other,)) = owner {
            if other != did {
                return Ok(AdminRegisterOutcome::SubdomainTaken);
            }
        }

        sqlx::query("DELETE FROM handles WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM secrets WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await?;

        sqlx::query("INSERT INTO secrets (did, secret_hash) VALUES (?1, ?2)")
            .bind(did)
            .bind(secret_hash)
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO handles (subdomain, did) VALUES (?1, ?2)")
            .bind(subdomain)
            .bind(did)
            .execute(&mut *conn)
            .await?;

        Ok(AdminRegisterOutcome::Registered)
    }
    .await;

    finish_tx(&mut conn, result).await
}

#[derive(Debug, PartialEq, Eq)]
pub enum RenameOutcome {
    Renamed { old_subdomain: String },
    NoChange,
    SubdomainTaken,
    HandleNotFound,
}

/// Rename is delete-old + insert-new in one transaction (D3, §6.2). The
/// caller is identified only by their DID — they cannot rename another user's
/// handle because they never specify which handle to change.
pub async fn try_rename(
    pool: &Pool,
    did: &str,
    new_subdomain: &str,
) -> Result<RenameOutcome, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<RenameOutcome, sqlx::Error> = async {
        let current: Option<(String,)> =
            sqlx::query_as("SELECT subdomain FROM handles WHERE did = ?1")
                .bind(did)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((current_sub,)) = current else {
            return Ok(RenameOutcome::HandleNotFound);
        };

        if current_sub == new_subdomain {
            return Ok(RenameOutcome::NoChange);
        }

        if sqlx::query("SELECT 1 FROM handles WHERE subdomain = ?1")
            .bind(new_subdomain)
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
        {
            return Ok(RenameOutcome::SubdomainTaken);
        }

        sqlx::query("DELETE FROM handles WHERE subdomain = ?1")
            .bind(&current_sub)
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO handles (subdomain, did) VALUES (?1, ?2)")
            .bind(new_subdomain)
            .bind(did)
            .execute(&mut *conn)
            .await?;

        Ok(RenameOutcome::Renamed { old_subdomain: current_sub })
    }
    .await;

    finish_tx(&mut conn, result).await
}

#[derive(Debug, PartialEq, Eq)]
pub struct WipeResult {
    pub handles_removed: u64,
    pub secret_removed: bool,
}

/// Remove every row for a DID: all handles, plus the secret. Returns zeros
/// when the DID had nothing — caller decides whether that's an error.
pub async fn wipe_did(pool: &Pool, did: &str) -> Result<WipeResult, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<WipeResult, sqlx::Error> = async {
        let handles_removed = sqlx::query("DELETE FROM handles WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        let secret_removed = sqlx::query("DELETE FROM secrets WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await?
            .rows_affected()
            > 0;

        Ok(WipeResult { handles_removed, secret_removed })
    }
    .await;

    finish_tx(&mut conn, result).await
}

// --- sessions ----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub csrf_token: String,
}

/// Single-session policy (D8, §6.8): every login wipes existing rows, then
/// inserts the new session. `ttl_secs` is added to the sqlite server clock at
/// insert time so there's no client-clock dependency.
pub async fn create_session(
    pool: &Pool,
    session_id: &str,
    csrf_token: &str,
    ttl_secs: i64,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<(), sqlx::Error> = async {
        sqlx::query("DELETE FROM sessions").execute(&mut *conn).await?;
        sqlx::query(
            "INSERT INTO sessions (session_id, csrf_token, expires_at) \
             VALUES (?1, ?2, datetime('now', ?3))",
        )
        .bind(session_id)
        .bind(csrf_token)
        .bind(format!("{ttl_secs:+} seconds"))
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .await;

    finish_tx(&mut conn, result).await
}

pub async fn find_active_session(
    pool: &Pool,
    session_id: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT csrf_token FROM sessions \
         WHERE session_id = ?1 AND expires_at > datetime('now')",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(csrf_token,)| SessionRow { csrf_token }))
}

pub async fn delete_all_sessions(pool: &Pool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions").execute(pool).await?;
    Ok(())
}

pub async fn delete_expired_sessions(pool: &Pool) -> Result<u64, sqlx::Error> {
    let n = sqlx::query("DELETE FROM sessions WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

// --- helpers -----------------------------------------------------------------

/// Commit on `Ok`, rollback on `Err`, always returning the original result.
/// Commit failure promotes to the returned error (the write didn't land).
async fn finish_tx<T>(
    conn: &mut sqlx::SqliteConnection,
    result: Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    match result {
        Ok(value) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(value)
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> Pool {
        let pool = connect("sqlite::memory:").await.expect("connect");
        migrate(&pool).await.expect("migrate");
        pool
    }

    #[tokio::test]
    async fn register_happy_path() {
        let pool = fresh().await;
        let out = try_register(&pool, "alice", "did:plc:a", "hash_a").await.unwrap();
        assert_eq!(out, RegisterOutcome::Registered);

        assert_eq!(
            find_did_by_subdomain(&pool, "alice").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        assert_eq!(
            find_did_by_secret_hash(&pool, "hash_a").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        assert_eq!(count_handles(&pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn register_refuses_taken_subdomain() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();
        let out = try_register(&pool, "alice", "did:plc:b", "h_b").await.unwrap();
        assert_eq!(out, RegisterOutcome::SubdomainTaken);
        // Did B should not have leaked a secret either.
        assert!(find_did_by_secret_hash(&pool, "h_b").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn register_refuses_did_with_existing_handle() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();
        let out = try_register(&pool, "bob", "did:plc:a", "h_a2").await.unwrap();
        assert_eq!(out, RegisterOutcome::DidHasHandle);
    }

    #[tokio::test]
    async fn register_refuses_did_with_stranded_secret() {
        // simulate the "DID has a secret but no handle" state (pre-port bug).
        let pool = fresh().await;
        sqlx::query("INSERT INTO secrets (did, secret_hash) VALUES (?1, ?2)")
            .bind("did:plc:a")
            .bind("h_a")
            .execute(&pool)
            .await
            .unwrap();

        let out = try_register(&pool, "alice", "did:plc:a", "h_other").await.unwrap();
        assert_eq!(out, RegisterOutcome::DidHasSecret);
    }

    #[tokio::test]
    async fn admin_register_wipes_and_replaces() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

        let out = try_register_admin(&pool, "alice2", "did:plc:a", "h_new").await.unwrap();
        assert_eq!(out, AdminRegisterOutcome::Registered);

        // Old handle gone, new one present.
        assert!(find_did_by_subdomain(&pool, "alice").await.unwrap().is_none());
        assert_eq!(
            find_did_by_subdomain(&pool, "alice2").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        // Secret replaced.
        assert_eq!(
            find_did_by_secret_hash(&pool, "h_new").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        assert!(find_did_by_secret_hash(&pool, "h_a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn admin_register_refuses_subdomain_owned_by_other_did() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

        let out = try_register_admin(&pool, "alice", "did:plc:b", "h_b").await.unwrap();
        assert_eq!(out, AdminRegisterOutcome::SubdomainTaken);

        // DID A's rows are untouched.
        assert_eq!(
            find_did_by_subdomain(&pool, "alice").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
    }

    #[tokio::test]
    async fn rename_replaces_atomically() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

        let out = try_rename(&pool, "did:plc:a", "alicia").await.unwrap();
        assert_eq!(out, RenameOutcome::Renamed { old_subdomain: "alice".into() });

        assert!(find_did_by_subdomain(&pool, "alice").await.unwrap().is_none());
        assert_eq!(
            find_did_by_subdomain(&pool, "alicia").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        assert_eq!(count_handles(&pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn rename_to_same_name_is_noop() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();
        let out = try_rename(&pool, "did:plc:a", "alice").await.unwrap();
        assert_eq!(out, RenameOutcome::NoChange);
    }

    #[tokio::test]
    async fn rename_refuses_taken_subdomain() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();
        try_register(&pool, "bob", "did:plc:b", "h_b").await.unwrap();

        let out = try_rename(&pool, "did:plc:a", "bob").await.unwrap();
        assert_eq!(out, RenameOutcome::SubdomainTaken);
        // Both originals intact.
        assert_eq!(
            find_did_by_subdomain(&pool, "alice").await.unwrap().as_deref(),
            Some("did:plc:a")
        );
        assert_eq!(
            find_did_by_subdomain(&pool, "bob").await.unwrap().as_deref(),
            Some("did:plc:b")
        );
    }

    #[tokio::test]
    async fn rename_missing_handle_is_distinct() {
        let pool = fresh().await;
        let out = try_rename(&pool, "did:plc:ghost", "nobody").await.unwrap();
        assert_eq!(out, RenameOutcome::HandleNotFound);
    }

    #[tokio::test]
    async fn wipe_removes_everything_and_reports() {
        let pool = fresh().await;
        try_register(&pool, "alice", "did:plc:a", "h_a").await.unwrap();

        let res = wipe_did(&pool, "did:plc:a").await.unwrap();
        assert_eq!(res, WipeResult { handles_removed: 1, secret_removed: true });

        assert!(find_did_by_subdomain(&pool, "alice").await.unwrap().is_none());
        assert!(find_did_by_secret_hash(&pool, "h_a").await.unwrap().is_none());

        // After wipe, DID can register fresh.
        let out = try_register(&pool, "alice2", "did:plc:a", "h_a2").await.unwrap();
        assert_eq!(out, RegisterOutcome::Registered);
    }

    #[tokio::test]
    async fn wipe_on_unknown_did_reports_zero() {
        let pool = fresh().await;
        let res = wipe_did(&pool, "did:plc:ghost").await.unwrap();
        assert_eq!(res, WipeResult { handles_removed: 0, secret_removed: false });
    }

    #[tokio::test]
    async fn session_create_and_lookup() {
        let pool = fresh().await;
        create_session(&pool, "sess_a", "csrf_a", 3600).await.unwrap();

        let row = find_active_session(&pool, "sess_a").await.unwrap().unwrap();
        assert_eq!(row.csrf_token, "csrf_a");
    }

    #[tokio::test]
    async fn session_replaces_previous_on_new_login() {
        let pool = fresh().await;
        create_session(&pool, "old", "csrf_old", 3600).await.unwrap();
        create_session(&pool, "new", "csrf_new", 3600).await.unwrap();

        assert!(find_active_session(&pool, "old").await.unwrap().is_none());
        assert!(find_active_session(&pool, "new").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn expired_session_not_returned() {
        let pool = fresh().await;
        // negative TTL: already expired at insert time
        create_session(&pool, "gone", "csrf_x", -10).await.unwrap();
        assert!(find_active_session(&pool, "gone").await.unwrap().is_none());

        let purged = delete_expired_sessions(&pool).await.unwrap();
        assert_eq!(purged, 1);
    }

    #[tokio::test]
    async fn list_handles_is_ordered_and_paginated() {
        let pool = fresh().await;
        for (sub, did) in [("charlie", "d3"), ("alice", "d1"), ("bob", "d2")] {
            try_register(&pool, sub, did, &format!("h_{did}")).await.unwrap();
        }

        let page1 = list_handles(&pool, 0, 2).await.unwrap();
        assert_eq!(page1.iter().map(|r| r.subdomain.as_str()).collect::<Vec<_>>(), ["alice", "bob"]);

        let page2 = list_handles(&pool, 2, 2).await.unwrap();
        assert_eq!(page2.iter().map(|r| r.subdomain.as_str()).collect::<Vec<_>>(), ["charlie"]);
    }
}
