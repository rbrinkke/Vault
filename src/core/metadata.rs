use crate::models::credential::CredentialMeta;
use crate::models::vault_config::{VaultFile, VaultSection};
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn load(path: &Path) -> Result<VaultFile> {
    if !path.exists() {
        return Ok(VaultFile::default());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("read vault metadata {}", path.display()))?;
    let mut vault: VaultFile = toml::from_str(&content)
        .with_context(|| format!("parse vault metadata {}", path.display()))?;
    if vault.vault.version == 0 {
        vault.vault.version = 1;
    }
    Ok(vault)
}

pub fn save(path: &Path, vault: &VaultFile) -> Result<()> {
    let content = toml::to_string_pretty(vault).context("serialize vault metadata")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(
        path.parent().unwrap_or_else(|| Path::new(".")),
    )
    .context("create temp vault metadata")?;
    tmp.write_all(content.as_bytes())
        .context("write vault metadata")?;
    tmp.flush().ok();

    #[cfg(unix)]
    {
        let perm = fs::Permissions::from_mode(0o600);
        tmp.as_file()
            .set_permissions(perm)
            .context("set permissions on temp vault metadata")?;
    }

    tmp.persist(path)
        .map_err(|err| anyhow::anyhow!("persist vault metadata: {}", err))?;
    Ok(())
}

pub fn upsert_credential(
    vault: &mut VaultFile,
    cred: CredentialMeta,
) {
    if let Some(existing) = vault.credentials.iter_mut().find(|c| c.name == cred.name) {
        *existing = cred;
    } else {
        vault.credentials.push(cred);
    }
    vault.credentials.sort_by(|a, b| a.name.cmp(&b.name));
}

pub fn remove_credential(vault: &mut VaultFile, name: &str) {
    vault.credentials.retain(|c| c.name != name);
}

pub fn ensure_vault_section(vault: &mut VaultFile, credstore_path: Option<String>) {
    if vault.vault.version == 0 {
        vault.vault = VaultSection::default();
    }
    if vault.vault.credstore_path.is_none() {
        vault.vault.credstore_path = credstore_path;
    }
}
