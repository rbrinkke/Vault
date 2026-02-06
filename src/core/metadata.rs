//! vault.toml persistence and credential metadata management.

use crate::constants;
use crate::models::credential::CredentialMeta;
use crate::models::vault_config::{VaultFile, VaultSection};
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Load vault metadata from a TOML file.
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

/// Save vault metadata to a TOML file atomically.
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
    tmp.flush().context("flush vault metadata")?;

    #[cfg(unix)]
    {
        let perm = fs::Permissions::from_mode(constants::VAULT_TOML_MODE);
        tmp.as_file()
            .set_permissions(perm)
            .context("set permissions on temp vault metadata")?;
    }

    tmp.persist(path)
        .map_err(|err| anyhow::anyhow!("persist vault metadata: {}", err))?;
    Ok(())
}

/// Insert or update a credential in the vault metadata.
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

/// Remove a credential from the vault metadata.
pub fn remove_credential(vault: &mut VaultFile, name: &str) {
    vault.credentials.retain(|c| c.name != name);
}

/// Ensure the vault section has default values.
pub fn ensure_vault_section(vault: &mut VaultFile, credstore_path: Option<String>) {
    if vault.vault.version == 0 {
        vault.vault = VaultSection::default();
    }
    if vault.vault.credstore_path.is_none() {
        vault.vault.credstore_path = credstore_path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_upsert_new_credential() {
        let mut vault = VaultFile::default();
        let cred = CredentialMeta {
            name: "test".into(),
            ..Default::default()
        };
        upsert_credential(&mut vault, cred);
        assert_eq!(vault.credentials.len(), 1);
        assert_eq!(vault.credentials[0].name, "test");
    }

    #[test]
    fn test_upsert_existing_credential() {
        let mut vault = VaultFile::default();
        let c1 = CredentialMeta {
            name: "test".into(),
            description: Some("old".into()),
            ..Default::default()
        };
        upsert_credential(&mut vault, c1);
        let c2 = CredentialMeta {
            name: "test".into(),
            description: Some("new".into()),
            ..Default::default()
        };
        upsert_credential(&mut vault, c2);
        assert_eq!(vault.credentials.len(), 1);
        assert_eq!(vault.credentials[0].description, Some("new".into()));
    }

    #[test]
    fn test_remove_credential() {
        let mut vault = VaultFile::default();
        upsert_credential(
            &mut vault,
            CredentialMeta {
                name: "a".into(),
                ..Default::default()
            },
        );
        upsert_credential(
            &mut vault,
            CredentialMeta {
                name: "b".into(),
                ..Default::default()
            },
        );
        remove_credential(&mut vault, "a");
        assert_eq!(vault.credentials.len(), 1);
        assert_eq!(vault.credentials[0].name, "b");
    }

    #[test]
    fn test_credentials_sorted_after_upsert() {
        let mut vault = VaultFile::default();
        upsert_credential(
            &mut vault,
            CredentialMeta {
                name: "z".into(),
                ..Default::default()
            },
        );
        upsert_credential(
            &mut vault,
            CredentialMeta {
                name: "a".into(),
                ..Default::default()
            },
        );
        assert_eq!(vault.credentials[0].name, "a");
        assert_eq!(vault.credentials[1].name, "z");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.toml");
        let mut vault = VaultFile::default();
        vault.vault.version = 1;
        upsert_credential(
            &mut vault,
            CredentialMeta {
                name: "test".into(),
                description: Some("desc".into()),
                ..Default::default()
            },
        );
        save(&path, &vault).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials[0].name, "test");
    }
}