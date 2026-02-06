//! Systemd drop-in generator from service map entries.

use crate::core::service_map::{self, ServiceMapEntry};
use anyhow::{Context, Result};
use std::path::Path;

/// Generate a systemd drop-in from a service map file.
///
/// Convenience wrapper that parses the map file, then generates the drop-in.
pub fn generate_dropin(
    map_file: &Path,
    cred_dir: &Path,
    no_env: bool,
    hardening: bool,
) -> Result<String> {
    let entries = service_map::parse_service_map(map_file, cred_dir)
        .with_context(|| format!("parse map file {}", map_file.display()))?;
    Ok(generate_dropin_from_entries(&entries, no_env, hardening))
}

/// Generate a systemd drop-in from pre-parsed entries (pure function).
pub fn generate_dropin_from_entries(
    entries: &[ServiceMapEntry],
    no_env: bool,
    hardening: bool,
) -> String {
    let mut out = String::new();
    out.push_str("[Service]\n");
    for entry in entries {
        out.push_str(&format!(
            "LoadCredentialEncrypted={}:{}\n",
            entry.cred_name,
            entry.cred_path.display()
        ));
        if !no_env {
            if let Some(env_var) = &entry.env_var {
                out.push_str(&format!(
                    "Environment={}=/run/credentials/%N/{}\n",
                    env_var, entry.cred_name
                ));
            }
        }
    }

    if hardening {
        out.push_str("NoNewPrivileges=yes\n");
        out.push_str("ProtectSystem=strict\n");
        out.push_str("ProtectHome=read-only\n");
        out.push_str("PrivateTmp=yes\n");
        out.push_str("ProtectKernelTunables=yes\n");
        out.push_str("ProtectKernelModules=yes\n");
        out.push_str("ProtectControlGroups=yes\n");
        out.push_str("LockPersonality=yes\n");
        out.push_str("MemoryDenyWriteExecute=yes\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_map(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_generate_basic_dropin() {
        let map = write_map("db_password DB_PASS_FILE\n");
        let result = generate_dropin(map.path(), Path::new("/creds"), false, false).unwrap();
        assert!(result.contains("[Service]"));
        assert!(result.contains("LoadCredentialEncrypted=db_password:/creds/db_password.cred"));
        assert!(result.contains("Environment=DB_PASS_FILE=/run/credentials/%N/db_password"));
    }

    #[test]
    fn test_generate_no_env() {
        let map = write_map("db_password DB_PASS_FILE\n");
        let result = generate_dropin(map.path(), Path::new("/creds"), true, false).unwrap();
        assert!(!result.contains("Environment="));
    }

    #[test]
    fn test_generate_with_hardening() {
        let map = write_map("db_password\n");
        let result = generate_dropin(map.path(), Path::new("/creds"), false, true).unwrap();
        assert!(result.contains("NoNewPrivileges=yes"));
        assert!(result.contains("ProtectSystem=strict"));
    }

    #[test]
    fn test_generate_comment_and_blank() {
        let map = write_map("# comment\n\ndb_password\n");
        let result = generate_dropin(map.path(), Path::new("/creds"), false, false).unwrap();
        assert!(result.contains("db_password"));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn test_empty_map_file() {
        let map = write_map("");
        let result = generate_dropin(map.path(), Path::new("/creds"), false, false).unwrap();
        assert_eq!(result, "[Service]\n");
    }

    #[test]
    fn test_generate_from_entries() {
        let entries = vec![
            ServiceMapEntry {
                cred_name: "db_pass".to_string(),
                cred_path: PathBuf::from("/creds/db_pass.cred"),
                env_var: Some("DB_PASS_FILE".to_string()),
                line_number: 1,
                is_custom_path: false,
            },
        ];
        let result = generate_dropin_from_entries(&entries, false, false);
        assert!(result.contains("LoadCredentialEncrypted=db_pass:/creds/db_pass.cred"));
        assert!(result.contains("Environment=DB_PASS_FILE=/run/credentials/%N/db_pass"));
    }
}
