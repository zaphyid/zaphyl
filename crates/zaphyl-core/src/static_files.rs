//! Static file serving: safe resolution of a request path to a file on disk.
//!
//! Path traversal is prevented two ways: only `Normal` path components are kept
//! (so `..`, absolute roots, and Windows prefixes are rejected), and the
//! resolved path is canonicalized and confirmed to stay under the root (which
//! also defeats symlink escapes).

use percent_encoding::percent_decode_str;
use std::path::{Component, Path, PathBuf};

/// A directory that static files are served from.
#[derive(Debug, Clone)]
pub struct StaticDir {
    root: PathBuf,
}

impl StaticDir {
    /// Create a static-file root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve `request_path` to an existing file under the root, or `None` if it
    /// does not exist or would escape the root. A directory resolves to its
    /// `index.html`.
    #[must_use]
    pub fn resolve(&self, request_path: &str) -> Option<PathBuf> {
        // Percent-decode so encoded traversal (`%2e%2e`) is normalized before the
        // component check below rejects it.
        let decoded = percent_decode_str(request_path).decode_utf8().ok()?;

        let mut candidate = self.root.clone();
        for component in Path::new(decoded.as_ref()).components() {
            match component {
                Component::Normal(part) => candidate.push(part),
                Component::CurDir | Component::RootDir => {}
                // Reject `..` and Windows prefixes outright.
                Component::ParentDir | Component::Prefix(_) => return None,
            }
        }

        if candidate.is_dir() {
            candidate.push("index.html");
        }

        // Canonicalize and confirm the result stays within the root.
        let real = candidate.canonicalize().ok()?;
        let root = self.root.canonicalize().ok()?;
        if real.starts_with(&root) && real.is_file() {
            Some(real)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StaticDir;
    use std::fs;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zaphyl-static-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("index.html"), "home").unwrap();
        fs::write(dir.join("sub/page.txt"), "nested").unwrap();
        dir
    }

    #[test]
    fn serves_index_for_directory() {
        let dir = temp_root("index");
        let resolved = StaticDir::new(&dir).resolve("/").expect("index");
        assert_eq!(fs::read_to_string(resolved).unwrap(), "home");
    }

    #[test]
    fn serves_nested_file() {
        let dir = temp_root("nested");
        let resolved = StaticDir::new(&dir).resolve("/sub/page.txt").expect("file");
        assert_eq!(fs::read_to_string(resolved).unwrap(), "nested");
    }

    #[test]
    fn decodes_percent_encoding() {
        let dir = temp_root("decode");
        // `/sub/page.txt` with an encoded slash and letter.
        let resolved = StaticDir::new(&dir).resolve("/sub/pa%67e.txt");
        assert!(resolved.is_some());
    }

    #[test]
    fn rejects_parent_traversal() {
        let dir = temp_root("traversal");
        assert!(StaticDir::new(&dir).resolve("/../secret").is_none());
        assert!(StaticDir::new(&dir).resolve("/sub/../../secret").is_none());
    }

    #[test]
    fn rejects_encoded_traversal() {
        let dir = temp_root("encoded");
        assert!(StaticDir::new(&dir).resolve("/%2e%2e/secret").is_none());
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_root("missing");
        assert!(StaticDir::new(&dir).resolve("/nope.txt").is_none());
    }
}
