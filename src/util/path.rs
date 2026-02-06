//! Path normalization without filesystem access.

use std::path::{Component, Path, PathBuf};

/// Normalize a path by resolving `.` and `..` components without filesystem access.
pub fn normalize(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                components.pop();
            }
            Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Check if `path` is contained within `root` after normalization.
pub fn is_within(path: &Path, root: &Path) -> bool {
    let normalized = normalize(path);
    let root_normalized = normalize(root);
    normalized.starts_with(&root_normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_simple() {
        assert_eq!(normalize(Path::new("/a/b/c")), PathBuf::from("/a/b/c"));
    }

    #[test]
    fn test_normalize_dotdot() {
        assert_eq!(normalize(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
    }

    #[test]
    fn test_normalize_dot() {
        assert_eq!(normalize(Path::new("/a/./b")), PathBuf::from("/a/b"));
    }

    #[test]
    fn test_is_within_true() {
        assert!(is_within(
            Path::new("/opt/vault/creds/x.cred"),
            Path::new("/opt/vault")
        ));
    }

    #[test]
    fn test_is_within_false_traversal() {
        assert!(!is_within(
            Path::new("/opt/vault/../../etc/passwd"),
            Path::new("/opt/vault")
        ));
    }

    #[test]
    fn test_is_within_exact() {
        assert!(is_within(
            Path::new("/opt/vault"),
            Path::new("/opt/vault")
        ));
    }
}
