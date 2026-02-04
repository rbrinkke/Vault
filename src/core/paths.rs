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
}

impl VaultPaths {
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
        Ok(Self::from_root(PathBuf::from("/opt/services/vault")))
    }

    pub fn from_root(root: PathBuf) -> Self {
        let credstore = root.join("credstore");
        let services = root.join("services");
        let units = root.join("units");
        let vault_toml = root.join("vault.toml");
        Self {
            root,
            credstore,
            services,
            units,
            vault_toml,
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
