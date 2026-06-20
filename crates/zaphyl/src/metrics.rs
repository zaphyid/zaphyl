//! Prometheus metrics, served by Pingora's metrics endpoint.

use prometheus::{IntCounterVec, register_int_counter_vec};
use std::sync::LazyLock;

/// Total proxied requests, labelled by response status class.
static REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zaphyl_requests_total",
        "Total proxied requests by response status class.",
        &["status_class"]
    )
    .expect("register zaphyl_requests_total")
});

/// Record a completed request by its response status code.
pub fn record(status: u16) {
    let class = match status {
        0 => "none",
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    REQUESTS.with_label_values(&[class]).inc();
}
