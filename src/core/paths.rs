//! Vault path resolution and directory structure.

use crate::constants;
use anyhow::{Context, Result};
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub root: PathBuf,
    pub credstore: PathBuf,
    pub services: PathBuf,
    pub units: PathBuf,
    pub vault_toml: PathBuf,
    pub vault_lock: PathBuf,
    pub audit_lock: PathBuf,
}

impl VaultPaths {
    /// Resolve vault paths from CLI arg, env var, or auto-detection.
    pub fn resolve(root_arg: Option<PathBuf>) -> Result<Self> {
        if let Some(root) = root_arg {
            return Ok(Self::from_root(root));
        }
        if let Ok(root) = env::var("GOAMET_VAULT_ROOT") {
            return Ok(Self::from_root(PathBuf::from(root)));
        }
        if let Some(found) = find_repo_root()? {
            return Ok(Self::from_root(found));
        }
        Ok(Self::from_root(PathBuf::from(constants::DEFAULT_VAULT_ROOT)))
    }

    /// Create vault paths from a root directory.
    pub fn from_root(root: PathBuf) -> Self {
        let credstore = root.join("credstore");
        let services = root.join("services");
        let units = root.join("units");
        let vault_toml = root.join("vault.toml");
        let vault_lock = root.join("vault.lock");
        let audit_lock = root.join("audit.lock");
        Self {
            root,
            credstore,
            services,
            units,
            vault_toml,
            vault_lock,
            audit_lock,
        }
    }
}

fn find_repo_root() -> Result<Option<PathBuf>> {
    let cwd = env::current_dir().context("resolve current directory")?;
    for ancestor in cwd.ancestors() {
        if looks_like_root(ancestor) {
            return Ok(Some(ancestor.to_path_buf()));
        }
    }
    Ok(None)
}

fn looks_like_root(path: &Path) -> bool {
    path.join("credstore").is_dir() && path.join("services").is_dir()
}

impl std::fmt::Display for VaultPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault@{}", self.root.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_root() {
        let paths = VaultPaths::from_root(PathBuf::from("/test"));
        assert_eq!(paths.root, PathBuf::from("/test"));
        assert_eq!(paths.credstore, PathBuf::from("/test/credstore"));
        assert_eq!(paths.services, PathBuf::from("/test/services"));
        assert_eq!(paths.units, PathBuf::from("/test/units"));
        assert_eq!(paths.vault_toml, PathBuf::from("/test/vault.toml"));
        assert_eq!(paths.vault_lock, PathBuf::from("/test/vault.lock"));
        assert_eq!(paths.audit_lock, PathBuf::from("/test/audit.lock"));
    }
}
