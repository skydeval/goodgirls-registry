//! Shared application state. Cheap to clone — `SqlitePool` and
//! `reqwest::Client` are already `Arc`-backed, so handler clones are pointer
//! bumps. The string fields are short config values; cloning them per
//! request is negligible.

use crate::atproto;
use crate::db;

#[derive(Clone)]
pub struct AppState {
    pub pool: db::Pool,
    pub atproto: atproto::Client,
    /// SHA-256 hex of the operator's chosen admin key. Compared against the
    /// hash of submitted keys; the cleartext admin key never lives in the
    /// process.
    pub admin_key_hash: String,
    /// e.g. `"goodgirls.onl"`. Used for subdomain extraction on the
    /// `.well-known` endpoint and for formatting handle strings.
    pub base_domain: String,
    /// Configurable honeypot path (D6). E.g. `"/gg"`.
    pub decoy_path: String,
}
