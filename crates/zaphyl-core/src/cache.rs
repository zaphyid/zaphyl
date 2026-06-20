//! A small, conservative in-memory response cache.
//!
//! Correctness over coverage: only plainly-safe responses are cached - `GET`
//! requests with no `Authorization`, `200` responses that carry an explicit
//! `Cache-Control: max-age=N` (N > 0) and are not `private`/`no-store`/
//! `no-cache` and set no cookies. Anything uncertain is not cached, so the cache
//! never serves private or stale data. `Vary` is honored for `Accept-Encoding`
//! (part of the key); responses varying on anything else are not cached. A
//! [`Lookup`] distinguishes fresh from stale entries so the proxy can revalidate
//! a stale entry with the origin (`If-None-Match`) instead of refetching.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Whether a request may be served from (and stored in) the cache.
#[must_use]
pub fn request_cacheable(
    method: &str,
    cache_control: Option<&str>,
    has_authorization: bool,
) -> bool {
    method == "GET"
        && !has_authorization
        && !has_directive(cache_control, "no-store")
        && !has_directive(cache_control, "no-cache")
}

/// The duration a response may be cached for, if it is cacheable at all.
///
/// `vary` is the response's `Vary` header: a response that varies on anything
/// other than `Accept-Encoding` (which the cache keys on) is not cached, so the
/// wrong variant is never served.
#[must_use]
pub fn response_ttl(
    status: u16,
    cache_control: Option<&str>,
    has_set_cookie: bool,
    vary: Option<&str>,
) -> Option<Duration> {
    if status != 200 || has_set_cookie || !vary_cacheable(vary) {
        return None;
    }
    if has_directive(cache_control, "no-store")
        || has_directive(cache_control, "no-cache")
        || has_directive(cache_control, "private")
    {
        return None;
    }
    match max_age(cache_control?) {
        Some(seconds) if seconds > 0 => Some(Duration::from_secs(seconds)),
        _ => None,
    }
}

/// Whether a response with this `Vary` may be cached: only when it varies on
/// nothing, or solely on `Accept-Encoding` (which is part of the cache key).
fn vary_cacheable(vary: Option<&str>) -> bool {
    match vary {
        None => true,
        Some(value) => {
            let value = value.trim();
            value != "*"
                && value
                    .split(',')
                    .all(|token| token.trim().eq_ignore_ascii_case("accept-encoding"))
        }
    }
}

/// A canonical form of `Accept-Encoding` for use in the cache key, so a gzipped
/// variant is never served to a client that did not ask for it.
#[must_use]
pub fn normalize_accept_encoding(accept_encoding: Option<&str>) -> String {
    let mut tokens: Vec<String> = accept_encoding
        .unwrap_or("")
        .split(',')
        .filter_map(|part| {
            let token = part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            (!token.is_empty()).then_some(token)
        })
        .collect();
    tokens.sort();
    tokens.dedup();
    tokens.join(",")
}

/// Whether a `Cache-Control` value lists the bare `directive` token.
fn has_directive(cache_control: Option<&str>, directive: &str) -> bool {
    cache_control.is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().split('=').next().unwrap_or("").trim() == directive)
    })
}

/// The `max-age=N` value from a `Cache-Control` header, if present.
fn max_age(cache_control: &str) -> Option<u64> {
    cache_control.split(',').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("max-age=")
            .and_then(|n| n.trim().parse::<u64>().ok())
    })
}

/// Whether an `If-None-Match` request header matches `etag` (weak comparison),
/// meaning a `304 Not Modified` may be returned instead of the body.
#[must_use]
pub fn if_none_match_satisfied(if_none_match: &str, etag: &str) -> bool {
    let if_none_match = if_none_match.trim();
    if if_none_match == "*" {
        return true;
    }
    let target = strip_weak(etag);
    if_none_match
        .split(',')
        .any(|candidate| strip_weak(candidate.trim()) == target)
}

/// Drop a leading weak-validator marker (`W/`) for weak ETag comparison.
fn strip_weak(etag: &str) -> &str {
    etag.trim().strip_prefix("W/").unwrap_or(etag).trim()
}

/// The outcome of a cache lookup.
#[derive(Debug)]
pub enum Lookup {
    /// No entry for the key.
    Miss,
    /// A fresh entry that may be served directly.
    Fresh(CachedResponse),
    /// An expired entry that may be revalidated with the origin.
    Stale(CachedResponse),
}

/// A stored response.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl CachedResponse {
    /// The entry's `ETag`, if any, used to revalidate it with the origin.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
            .map(|(_, value)| value.as_str())
    }
}

/// A bounded, thread-safe response cache: an in-memory map keyed by request,
/// optionally backed by a disk tier so entries survive a restart.
#[derive(Debug)]
pub struct ResponseCache {
    max_entries: usize,
    entries: Mutex<HashMap<String, (SystemTime, CachedResponse)>>,
    disk: Option<DiskStore>,
}

impl ResponseCache {
    /// Create an in-memory cache holding at most `max_entries` responses.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
            disk: None,
        }
    }

    /// Create a cache that also persists entries under `dir`.
    #[must_use]
    pub fn with_disk(max_entries: usize, dir: PathBuf) -> Self {
        Self {
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
            disk: Some(DiskStore::new(dir, max_entries)),
        }
    }

    /// The cache key for a request, incorporating a canonical `Accept-Encoding`
    /// so different content-codings are cached separately.
    #[must_use]
    pub fn key(host: &str, path_and_query: &str, accept_encoding: Option<&str>) -> String {
        // `\x1f` (unit separator) cannot appear in a host or URL.
        format!(
            "{host}{path_and_query}\x1f{}",
            normalize_accept_encoding(accept_encoding)
        )
    }

    /// Return a fresh cached response for `key`, or `None`.
    #[must_use]
    pub fn get(&self, key: &str, now: SystemTime) -> Option<CachedResponse> {
        match self.lookup(key, now) {
            Lookup::Fresh(response) => Some(response),
            Lookup::Stale(_) | Lookup::Miss => None,
        }
    }

    /// Look up `key`, distinguishing a fresh hit from a stale one (present but
    /// expired) so the caller can revalidate. Falls back to the disk tier and
    /// re-populates memory on a hit.
    #[must_use]
    pub fn lookup(&self, key: &str, now: SystemTime) -> Lookup {
        {
            let entries = self.entries.lock().expect("cache lock poisoned");
            if let Some((expiry, response)) = entries.get(key) {
                return if *expiry > now {
                    Lookup::Fresh(response.clone())
                } else {
                    Lookup::Stale(response.clone())
                };
            }
        }
        if let Some(disk) = &self.disk
            && let Some((expiry, response)) = disk.get(key)
        {
            self.insert_memory(key.to_owned(), expiry, response.clone());
            return if expiry > now {
                Lookup::Fresh(response)
            } else {
                Lookup::Stale(response)
            };
        }
        Lookup::Miss
    }

    /// Store `response` under `key` until `expiry`, in memory and (if enabled)
    /// on disk.
    pub fn put(&self, key: String, expiry: SystemTime, response: CachedResponse) {
        if let Some(disk) = &self.disk {
            disk.put(&key, expiry, &response);
        }
        self.insert_memory(key, expiry, response);
    }

    /// Insert into the in-memory map, evicting the soonest-to-expire entry when
    /// full.
    fn insert_memory(&self, key: String, expiry: SystemTime, response: CachedResponse) {
        let mut entries = self.entries.lock().expect("cache lock poisoned");
        if entries.len() >= self.max_entries
            && !entries.contains_key(&key)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (expiry, _))| *expiry)
                .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(key, (expiry, response));
    }
}

/// A disk-backed tier of the cache: one file per entry, written atomically.
#[derive(Debug)]
struct DiskStore {
    dir: PathBuf,
    max_entries: usize,
}

impl DiskStore {
    fn new(dir: PathBuf, max_entries: usize) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            max_entries: max_entries.max(1),
        }
    }

    fn path(&self, key: &str) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.dir.join(format!("{:016x}", hasher.finish()))
    }

    fn get(&self, key: &str) -> Option<(SystemTime, CachedResponse)> {
        let bytes = std::fs::read(self.path(key)).ok()?;
        let (stored_key, expiry, response) = decode(&bytes)?;
        // Guard against the (rare) hash collision.
        (stored_key == key).then_some((expiry, response))
    }

    fn put(&self, key: &str, expiry: SystemTime, response: &CachedResponse) {
        self.evict();
        let path = self.path(key);
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, encode(key, expiry, response)).is_ok() {
            // Rename is atomic, so a reader never sees a half-written file.
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    fn evict(&self) {
        let mut files: Vec<(SystemTime, PathBuf)> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                // Skip in-progress `.tmp` files.
                let modified = entry.metadata().ok()?.modified().ok()?;
                path.extension().is_none().then_some((modified, path))
            })
            .collect();
        if files.len() >= self.max_entries {
            files.sort_by_key(|(modified, _)| *modified);
            if let Some((_, oldest)) = files.into_iter().next() {
                let _ = std::fs::remove_file(oldest);
            }
        }
    }
}

/// Serialize a cache entry: key, expiry, status, headers, body.
fn encode(key: &str, expiry: SystemTime, response: &CachedResponse) -> Vec<u8> {
    let expiry_unix = expiry.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut out = Vec::new();
    write_bytes(&mut out, key.as_bytes());
    out.extend_from_slice(&expiry_unix.to_le_bytes());
    out.extend_from_slice(&response.status.to_le_bytes());
    out.extend_from_slice(&(response.headers.len() as u32).to_le_bytes());
    for (name, value) in &response.headers {
        write_bytes(&mut out, name.as_bytes());
        write_bytes(&mut out, value.as_bytes());
    }
    out.extend_from_slice(&(response.body.len() as u64).to_le_bytes());
    out.extend_from_slice(&response.body);
    out
}

/// Length-prefix and append a byte string.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Deserialize a cache entry written by [`encode`], or `None` if truncated.
fn decode(buf: &[u8]) -> Option<(String, SystemTime, CachedResponse)> {
    let mut reader = Reader { buf, pos: 0 };
    let key = reader.string()?;
    let expiry = UNIX_EPOCH + Duration::from_secs(reader.u64()?);
    let status = reader.u16()?;
    let header_count = reader.u32()? as usize;
    // Bound the pre-allocation by what the remaining buffer could actually hold
    // (each header is two length-prefixed strings, so at least 8 bytes). A
    // corrupt or hostile length therefore can't trigger a huge allocation; if the
    // count is genuinely larger, the loop below grows the vec as it reads.
    let mut headers = Vec::with_capacity(header_count.min(reader.remaining() / 8));
    for _ in 0..header_count {
        let name = reader.string()?;
        let value = reader.string()?;
        headers.push((name, value));
    }
    let body_len = reader.u64()? as usize;
    let body = reader.take(body_len)?.to_vec();
    Some((
        key,
        expiry,
        CachedResponse {
            status,
            headers,
            body,
        },
    ))
}

/// A bounds-checked little-endian reader over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Bytes not yet consumed.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        Some(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedResponse, ResponseCache, request_cacheable, response_ttl};
    use std::time::{Duration, SystemTime};

    #[test]
    fn decode_rejects_hostile_header_count_without_oom() {
        // A buffer that parses a key, expiry, and status, then claims ~4.29
        // billion headers but supplies no header data. `decode` must return
        // `None` (truncated) without attempting a huge pre-allocation.
        let mut buf = Vec::new();
        super::write_bytes(&mut buf, b"k");
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&200u16.to_le_bytes());
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(super::decode(&buf).is_none());
    }

    #[test]
    fn decode_round_trips_a_response() {
        // A well-formed entry survives an encode/decode round trip.
        let response = CachedResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: b"hello".to_vec(),
        };
        let expiry = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let encoded = super::encode("the-key", expiry, &response);
        let (key, decoded_expiry, decoded) = super::decode(&encoded).unwrap();
        assert_eq!(key, "the-key");
        assert_eq!(decoded_expiry, expiry);
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.headers, response.headers);
        assert_eq!(decoded.body, response.body);
    }

    #[test]
    fn decode_rejects_truncated_buffers() {
        // Every prefix of a valid encoding shorter than the whole must decode to
        // `None` rather than panic.
        let response = CachedResponse {
            status: 204,
            headers: vec![("x".to_owned(), "y".to_owned())],
            body: b"body".to_vec(),
        };
        let encoded = super::encode("k", SystemTime::UNIX_EPOCH, &response);
        for len in 0..encoded.len() {
            assert!(
                super::decode(&encoded[..len]).is_none(),
                "prefix of length {len} should not decode"
            );
        }
        assert!(super::decode(&encoded).is_some());
    }

    #[test]
    fn only_get_without_auth_is_cacheable() {
        assert!(request_cacheable("GET", None, false));
        assert!(!request_cacheable("POST", None, false));
        assert!(!request_cacheable("GET", None, true));
        assert!(!request_cacheable("GET", Some("no-store"), false));
        assert!(!request_cacheable("GET", Some("no-cache"), false));
    }

    #[test]
    fn response_ttl_requires_explicit_max_age() {
        assert_eq!(
            response_ttl(200, Some("max-age=60"), false, None),
            Some(Duration::from_secs(60))
        );
        assert_eq!(response_ttl(200, Some("public"), false, None), None);
        assert_eq!(response_ttl(200, None, false, None), None);
    }

    #[test]
    fn uncacheable_responses_return_none() {
        assert_eq!(response_ttl(500, Some("max-age=60"), false, None), None);
        assert_eq!(response_ttl(200, Some("max-age=60"), true, None), None);
        assert_eq!(
            response_ttl(200, Some("private, max-age=60"), false, None),
            None
        );
        assert_eq!(
            response_ttl(200, Some("no-store, max-age=60"), false, None),
            None
        );
        assert_eq!(response_ttl(200, Some("max-age=0"), false, None), None);
    }

    #[test]
    fn vary_other_than_accept_encoding_is_not_cached() {
        // Vary on Accept-Encoding is fine (the key includes it).
        assert!(response_ttl(200, Some("max-age=60"), false, Some("Accept-Encoding")).is_some());
        // Anything else, or `*`, is not cached.
        assert_eq!(
            response_ttl(200, Some("max-age=60"), false, Some("Accept-Language")),
            None
        );
        assert_eq!(
            response_ttl(200, Some("max-age=60"), false, Some("*")),
            None
        );
        assert_eq!(
            response_ttl(
                200,
                Some("max-age=60"),
                false,
                Some("Accept-Encoding, Cookie")
            ),
            None
        );
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        use super::if_none_match_satisfied;
        assert!(if_none_match_satisfied("\"abc\"", "\"abc\""));
        assert!(if_none_match_satisfied("*", "\"abc\""));
        assert!(if_none_match_satisfied("\"x\", \"abc\"", "\"abc\""));
        assert!(if_none_match_satisfied("W/\"abc\"", "\"abc\""));
        assert!(!if_none_match_satisfied("\"other\"", "\"abc\""));
    }

    #[test]
    fn key_separates_by_accept_encoding() {
        let plain = ResponseCache::key("h", "/p", None);
        let gzip = ResponseCache::key("h", "/p", Some("gzip"));
        assert_ne!(plain, gzip);
        // Token order and casing do not matter.
        assert_eq!(
            ResponseCache::key("h", "/p", Some("gzip, br")),
            ResponseCache::key("h", "/p", Some("BR,GZIP"))
        );
    }

    fn response(body: &str) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn stores_and_serves_fresh_entries() {
        let cache = ResponseCache::new(8);
        let now = SystemTime::now();
        cache.put(
            "k".to_owned(),
            now + Duration::from_secs(60),
            response("hi"),
        );
        assert_eq!(cache.get("k", now).unwrap().body, b"hi");
    }

    #[test]
    fn expired_entries_are_dropped() {
        let cache = ResponseCache::new(8);
        let now = SystemTime::now();
        cache.put("k".to_owned(), now + Duration::from_secs(1), response("hi"));
        // Query at a time past the expiry.
        assert!(cache.get("k", now + Duration::from_secs(2)).is_none());
    }

    #[test]
    fn evicts_when_full() {
        let cache = ResponseCache::new(2);
        let now = SystemTime::now();
        cache.put("a".to_owned(), now + Duration::from_secs(10), response("a"));
        cache.put("b".to_owned(), now + Duration::from_secs(20), response("b"));
        cache.put("c".to_owned(), now + Duration::from_secs(30), response("c"));
        // `a` expired soonest, so it was evicted to make room for `c`.
        assert!(cache.get("a", now).is_none());
        assert!(cache.get("b", now).is_some());
        assert!(cache.get("c", now).is_some());
    }

    #[test]
    fn lookup_distinguishes_fresh_from_stale() {
        use super::Lookup;
        let cache = ResponseCache::new(8);
        let now = SystemTime::now();
        cache.put(
            "k".to_owned(),
            now + Duration::from_secs(60),
            response("hi"),
        );
        assert!(matches!(cache.lookup("k", now), Lookup::Fresh(_)));
        // Past expiry the entry is stale (kept for revalidation), not a miss.
        assert!(matches!(
            cache.lookup("k", now + Duration::from_secs(120)),
            Lookup::Stale(_)
        ));
        assert!(matches!(cache.lookup("absent", now), Lookup::Miss));
    }

    #[test]
    fn cached_response_exposes_etag() {
        let entry = CachedResponse {
            status: 200,
            headers: vec![("ETag".to_owned(), "\"v1\"".to_owned())],
            body: vec![],
        };
        assert_eq!(entry.etag(), Some("\"v1\""));
    }

    #[test]
    fn disk_tier_survives_a_new_cache() {
        let dir = std::env::temp_dir().join("zaphyl-cache-disk-test");
        let _ = std::fs::remove_dir_all(&dir);
        let now = SystemTime::now();
        let entry = CachedResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: b"persisted".to_vec(),
        };

        // Store via one cache, then read it back through a fresh cache (cold
        // memory) pointed at the same directory.
        ResponseCache::with_disk(8, dir.clone()).put(
            "k".to_owned(),
            now + Duration::from_secs(60),
            entry,
        );
        let reloaded = ResponseCache::with_disk(8, dir.clone()).get("k", now);
        let reloaded = reloaded.expect("entry loaded from disk");
        assert_eq!(reloaded.body, b"persisted");
        assert_eq!(
            reloaded.headers,
            [("content-type".to_owned(), "text/plain".to_owned())]
        );

        // An expired disk entry is not served.
        assert!(
            ResponseCache::with_disk(8, dir)
                .get("k", now + Duration::from_secs(120))
                .is_none()
        );
    }
}
