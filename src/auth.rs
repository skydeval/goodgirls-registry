//! Hashing, key generation, session tokens, CSRF verification.
//!
//! - SHA-256 everywhere (D21). One algorithm, no argon2, no per-call salt.
//!   The security argument rests on the key having enough entropy that a
//!   preimage search is infeasible — see `key_entropy_meets_threshold` (D15).
//! - Key generation uses rejection sampling to eliminate the modulo bias the
//!   worker had (D10, §6.11).
//! - Session + CSRF tokens are 256 bits of OS randomness, hex-encoded (D8).

use sha2::{Digest, Sha256};

/// Readable alphabet carried over from the worker: no visually ambiguous
/// glyphs (no i/l/o, no 0/1). The design doc says "30-character" but the
/// actual string the worker shipped is 31 chars — we match what's live so
/// key appearance doesn't change. Changing this changes key entropy; the
/// test below catches a too-small alphabet.
pub const KEY_ALPHABET: &[u8; 31] = b"abcdefghjkmnpqrstuvwxyz23456789";
pub const KEY_LEN: usize = 24;

/// Largest multiple of the alphabet size that fits in a byte (31 * 8 = 248).
/// Bytes in [248, 256) are discarded so every alphabet index stays equally
/// likely — this is what kills the worker's modulo bias.
const REJECT_THRESHOLD: u8 = 248;
/// With P(reject) = 16/256, ten retries fail with probability ≈ 9e-13. If we
/// ever hit that, the OS CSPRNG is misbehaving and we want a loud crash, not
/// a silently biased key.
const MAX_RETRIES: u8 = 10;

/// Session lifetime. Admin sessions are short-lived single-slot (D8) — one
/// admin, one session row, new login replaces old.
pub const SESSION_TTL_SECS: u64 = 60 * 60 * 12;

/// Name of the session cookie. Kept here so handlers and the cookie builder
/// agree.
pub const SESSION_COOKIE_NAME: &str = "session";

/// Header clients must send on every admin POST (D8).
pub const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// SHA-256 of the input, hex-encoded lowercase. Stable wire format — the
/// worker's hashes import cleanly into the rust port's `secrets` table
/// without rehashing (§9 cutover).
pub fn hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    encode_hex(&digest)
}

/// Constant-time hash comparison. Both inputs are expected to be hex strings
/// of the same length, but we defend against the malformed case explicitly.
pub fn hashes_equal(a: &str, b: &str) -> bool {
    const_time_eq(a.as_bytes(), b.as_bytes())
}

/// Generate a fresh goodgirls key: 24 chars drawn uniformly from the readable
/// alphabet via rejection sampling (D10).
pub fn generate_key() -> String {
    use rand::{RngCore, rngs::OsRng};

    let mut out = String::with_capacity(KEY_LEN);
    let mut buf = [0u8; 1];

    for _ in 0..KEY_LEN {
        let mut accepted = false;
        for _ in 0..MAX_RETRIES {
            OsRng.fill_bytes(&mut buf);
            if buf[0] < REJECT_THRESHOLD {
                let idx = (buf[0] % KEY_ALPHABET.len() as u8) as usize;
                out.push(KEY_ALPHABET[idx] as char);
                accepted = true;
                break;
            }
        }
        assert!(
            accepted,
            "rejection sampling exhausted {MAX_RETRIES} retries — OS CSPRNG is misbehaving"
        );
    }
    out
}

/// 32 random bytes, hex-encoded — used for both session IDs and CSRF tokens.
/// 256 bits of entropy, safe to store and transmit (D8).
pub fn generate_token() -> String {
    use rand::{RngCore, rngs::OsRng};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

/// Build the `Set-Cookie` value for a fresh session (D8).
pub fn session_cookie(session_id: &str) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age={SESSION_TTL_SECS}"
    )
}

/// Build the `Set-Cookie` value that expires the session immediately.
pub fn clear_session_cookie() -> String {
    format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0"
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D15 / §6.15: SHA-256-only storage is safe because the key space has
    /// enough entropy. If anyone shortens `KEY_LEN` or shrinks `KEY_ALPHABET`
    /// below ~100 bits, this test trips and explains why.
    #[test]
    fn key_entropy_meets_threshold() {
        let bits = (KEY_LEN as f64) * (KEY_ALPHABET.len() as f64).log2();
        assert!(
            bits >= 100.0,
            "goodgirls key has only {bits:.1} bits of entropy — SHA-256-only secret storage requires at least 100. Shortened KEY_LEN or shrunk KEY_ALPHABET?"
        );
    }

    #[test]
    fn hash_matches_worker_output() {
        // The worker produced `sha256(utf8(input))` hex-encoded lowercase. We
        // must match it byte-for-byte so existing secret_hash rows validate.
        // Reference value computed with `echo -n "hello" | sha256sum`.
        assert_eq!(
            hash("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        // Deterministic.
        assert_eq!(hash("goodgirls"), hash("goodgirls"));
    }

    #[test]
    fn hashes_equal_is_length_checked() {
        let h = hash("x");
        assert!(hashes_equal(&h, &h));
        assert!(!hashes_equal(&h, &hash("y")));
        assert!(!hashes_equal(&h, "short"));
        assert!(!hashes_equal(&h, ""));
    }

    #[test]
    fn generated_key_has_expected_shape() {
        let k = generate_key();
        assert_eq!(k.len(), KEY_LEN);
        assert!(
            k.bytes().all(|b| KEY_ALPHABET.contains(&b)),
            "key {k:?} contains a char outside the alphabet"
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        // Not a real entropy test, but catches the trivially-broken case of
        // a deterministic generator.
        let a = generate_key();
        let b = generate_key();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_token_is_64_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn encode_hex_pads_single_digits() {
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xff, 0xab]), "000fffab");
    }

    #[test]
    fn session_cookie_carries_required_flags() {
        let c = session_cookie("abcd");
        assert!(c.starts_with("session=abcd"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Secure"));
        assert!(c.contains("Path=/"));
        assert!(c.contains(&format!("Max-Age={SESSION_TTL_SECS}")));
    }

    #[test]
    fn clear_cookie_zeroes_max_age() {
        let c = clear_session_cookie();
        assert!(c.contains("Max-Age=0"));
        assert!(c.starts_with("session=;"));
    }
}
