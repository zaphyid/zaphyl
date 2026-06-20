//! Core library for Zaphyl: routing, ACME challenge support, and (later) the
//! shared request model.

pub mod access;
pub mod acme;
pub mod cache;
pub mod ratelimit;
pub mod router;
pub mod static_files;

/// Zaphyl's version, taken from Cargo at compile time.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The project name.
#[must_use]
pub fn name() -> &'static str {
    "Zaphyl"
}

#[cfg(test)]
mod tests {
    use super::{name, version};

    #[test]
    fn version_matches_cargo_metadata() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }

    #[test]
    fn name_is_zaphyl() {
        assert_eq!(name(), "Zaphyl");
    }
}
