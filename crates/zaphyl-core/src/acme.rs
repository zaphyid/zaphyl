//! HTTP-01 ACME challenge support.
//!
//! When obtaining a certificate, the ACME server proves we control a domain by
//! fetching a token from `/.well-known/acme-challenge/<token>`. The ACME client
//! registers the token here; the proxy serves it; the client removes it once
//! validation completes.

use std::collections::HashMap;
use std::sync::RwLock;

/// The path prefix the ACME server fetches HTTP-01 challenges from.
const WELL_KNOWN_PREFIX: &str = "/.well-known/acme-challenge/";

/// Thread-safe store of pending HTTP-01 challenges (token to key authorization).
#[derive(Debug, Default)]
pub struct ChallengeStore {
    tokens: RwLock<HashMap<String, String>>,
}

impl ChallengeStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a challenge token and the key authorization to serve for it.
    pub fn insert(&self, token: impl Into<String>, key_authorization: impl Into<String>) {
        self.tokens
            .write()
            .expect("challenge store lock poisoned")
            .insert(token.into(), key_authorization.into());
    }

    /// Remove a challenge once it is no longer needed.
    pub fn remove(&self, token: &str) {
        self.tokens
            .write()
            .expect("challenge store lock poisoned")
            .remove(token);
    }

    /// If `path` is an HTTP-01 challenge for a known token, return the body to
    /// serve (the key authorization); otherwise `None`.
    #[must_use]
    pub fn response_for(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(WELL_KNOWN_PREFIX)?;
        if token.is_empty() || token.contains('/') {
            return None;
        }
        self.tokens
            .read()
            .expect("challenge store lock poisoned")
            .get(token)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::ChallengeStore;

    fn store() -> ChallengeStore {
        let store = ChallengeStore::new();
        store.insert("tok123", "tok123.keyauth");
        store
    }

    #[test]
    fn serves_known_challenge() {
        assert_eq!(
            store()
                .response_for("/.well-known/acme-challenge/tok123")
                .as_deref(),
            Some("tok123.keyauth")
        );
    }

    #[test]
    fn unknown_token_is_none() {
        assert_eq!(
            store().response_for("/.well-known/acme-challenge/other"),
            None
        );
    }

    #[test]
    fn non_challenge_path_is_none() {
        assert_eq!(store().response_for("/index.html"), None);
        assert_eq!(store().response_for("/.well-known/acme-challenge/"), None);
    }

    #[test]
    fn nested_token_is_none() {
        // A token must be a single path segment.
        assert_eq!(
            store().response_for("/.well-known/acme-challenge/tok123/extra"),
            None
        );
    }

    #[test]
    fn remove_deletes_challenge() {
        let store = store();
        store.remove("tok123");
        assert_eq!(
            store.response_for("/.well-known/acme-challenge/tok123"),
            None
        );
    }
}
