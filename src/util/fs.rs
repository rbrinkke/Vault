//! Filesystem helpers with permission management.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Create a directory if it doesn't exist and set permissions.
pub fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("create directory {}", path.display()))?;
    }
    set_permissions(path, mode)
}

/// Set file permissions (Unix only).
pub fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let perm = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perm)
            .with_context(|| format!("set permissions {:o} on {}", mode, path.display()))?;
    }
    Ok(())
}
