//! A fixed-window rate limiter keyed by an arbitrary string (e.g. a client IP).
//!
//! Time is passed in explicitly (`now_ms`) so the logic is fully deterministic
//! and unit-testable without sleeping.

use std::collections::HashMap;
use std::sync::Mutex;

/// Allows at most `max` events per `window_ms` milliseconds, per key.
#[derive(Debug)]
pub struct RateLimiter {
    window_ms: u64,
    max: u32,
    windows: Mutex<HashMap<String, Window>>,
}

#[derive(Debug)]
struct Window {
    start_ms: u64,
    count: u32,
}

impl RateLimiter {
    /// Create a limiter allowing `max` events per `window_ms` per key.
    #[must_use]
    pub fn new(window_ms: u64, max: u32) -> Self {
        Self {
            window_ms,
            max,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Record an event for `key` at `now_ms`; returns `true` if it is within the
    /// limit, `false` if the limit for the current window is exceeded.
    pub fn check(&self, key: &str, now_ms: u64) -> bool {
        let mut windows = self.windows.lock().expect("rate limiter lock poisoned");
        let window = windows.entry(key.to_owned()).or_insert(Window {
            start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(window.start_ms) >= self.window_ms {
            window.start_ms = now_ms;
            window.count = 0;
        }
        if window.count < self.max {
            window.count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let limiter = RateLimiter::new(1000, 3);
        assert!(limiter.check("a", 0));
        assert!(limiter.check("a", 100));
        assert!(limiter.check("a", 200));
        assert!(!limiter.check("a", 300));
    }

    #[test]
    fn resets_after_window() {
        let limiter = RateLimiter::new(1000, 1);
        assert!(limiter.check("a", 0));
        assert!(!limiter.check("a", 500));
        assert!(limiter.check("a", 1000));
    }

    #[test]
    fn keys_are_independent() {
        let limiter = RateLimiter::new(1000, 1);
        assert!(limiter.check("a", 0));
        assert!(limiter.check("b", 0));
        assert!(!limiter.check("a", 0));
    }
}
