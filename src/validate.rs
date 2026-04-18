//! Subdomain validation (D1, §6.1).
//!
//! Each failure maps to a distinct `Code`, so the client can distinguish *why*
//! a name was rejected without us having to build sentence fragments.
//!
//! Callers must pass the input already trimmed and lowercased — normalization
//! is a handler concern, validation is not.

use crate::error::{ApiError, ApiResult, Code};

pub const MIN_LEN: usize = 3;
/// DNS labels max out at 63 bytes. `.goodgirls.onl` is 14. The registrable
/// prefix therefore maxes at 49.
pub const MAX_LEN: usize = 49;

/// Exact-match reserved labels. Anything on this list is structurally
/// off-limits regardless of the operator's blocklist.
pub const RESERVED: &[&str] = &[
    "admin",
    "root",
    "administrator",
    "moderator",
    "support",
    "abuse",
    "postmaster",
    "webmaster",
    "localhost",
    "goodgirls",
];

/// Substring blocklist. A subdomain is rejected if any entry appears anywhere
/// inside it. Hardcoded (D1): extending the list requires a recompile and
/// redeploy, which is the point — the admin can always wipe a slipped-through
/// handle, but adding a term is a deliberate operator action.
pub const BLOCKED_KEYWORDS: &[&str] = &[
    "nigger",
    "nigga",
    "faggot",
    "retard",
];

pub fn subdomain(s: &str) -> ApiResult<()> {
    if s.len() < MIN_LEN {
        return Err(ApiError::new(Code::SubdomainTooShort));
    }
    if s.len() > MAX_LEN {
        return Err(ApiError::new(Code::SubdomainTooLong));
    }

    if !s
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(ApiError::new(Code::SubdomainInvalidChars));
    }

    if s.starts_with('-') || s.ends_with('-') || s.contains("--") {
        return Err(ApiError::new(Code::SubdomainHyphenRules));
    }

    if RESERVED.iter().any(|r| *r == s) {
        return Err(ApiError::new(Code::SubdomainReserved));
    }

    if BLOCKED_KEYWORDS.iter().any(|k| s.contains(k)) {
        return Err(ApiError::new(Code::SubdomainBlocked));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(s: &str) -> Code {
        subdomain(s).unwrap_err().code
    }

    #[test]
    fn accepts_typical_names() {
        for ok in [
            "alice",
            "a1b",
            "goodgirl",
            "the-cat-sat",
            "z".repeat(MAX_LEN).as_str(),
            "abc",
        ] {
            assert!(subdomain(ok).is_ok(), "expected {ok:?} to pass");
        }
    }

    #[test]
    fn length_bounds() {
        assert_eq!(code("ab"), Code::SubdomainTooShort);
        assert_eq!(code(""), Code::SubdomainTooShort);
        assert_eq!(code(&"a".repeat(MAX_LEN + 1)), Code::SubdomainTooLong);
    }

    #[test]
    fn character_set() {
        assert_eq!(code("Alice"), Code::SubdomainInvalidChars);
        assert_eq!(code("a_b"), Code::SubdomainInvalidChars);
        assert_eq!(code("a.b"), Code::SubdomainInvalidChars);
        assert_eq!(code("café"), Code::SubdomainInvalidChars);
        assert_eq!(code("a b"), Code::SubdomainInvalidChars);
    }

    #[test]
    fn hyphen_rules() {
        assert_eq!(code("-abc"), Code::SubdomainHyphenRules);
        assert_eq!(code("abc-"), Code::SubdomainHyphenRules);
        assert_eq!(code("ab--cd"), Code::SubdomainHyphenRules);
    }

    #[test]
    fn reserved_words_exact_match_only() {
        assert_eq!(code("admin"), Code::SubdomainReserved);
        assert_eq!(code("goodgirls"), Code::SubdomainReserved);
        // substring of a reserved word is fine — only exact matches are reserved
        assert!(subdomain("admins").is_ok());
        assert!(subdomain("goodgirlz").is_ok());
    }

    #[test]
    fn blocked_keywords_match_as_substring() {
        assert_eq!(code("nigger"), Code::SubdomainBlocked);
        assert_eq!(code("xx-faggot-xx"), Code::SubdomainBlocked);
        assert_eq!(code("prefixretard"), Code::SubdomainBlocked);
    }

    #[test]
    fn rules_apply_in_declared_order() {
        // too-short wins over invalid char
        assert_eq!(code("A"), Code::SubdomainTooShort);
        // invalid char wins over hyphen rules
        assert_eq!(code("-A-"), Code::SubdomainInvalidChars);
    }
}
