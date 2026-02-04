use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DropinEntry {
    pub name: String,
    pub cred_path: PathBuf,
    pub env_var: Option<String>,
}

pub fn generate_dropin(
    map_file: &Path,
    cred_dir: &Path,
    no_env: bool,
    hardening: bool,
) -> Result<String> {
    let content = fs::read_to_string(map_file)
        .with_context(|| format!("read map file {}", map_file.display()))?;
    let mut entries = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let raw = match parts.next() {
            Some(val) => val,
            None => continue,
        };
        let env_var = parts.next().map(|s| s.to_string());

        let (name, cred_path) = if let Some((left, right)) = raw.split_once(':') {
            (left.to_string(), PathBuf::from(right))
        } else {
            (raw.to_string(), cred_dir.join(format!("{}.cred", raw)))
        };

        if name.is_empty() {
            bail!("invalid credential name on line {}", idx + 1);
        }

        if cred_path.to_string_lossy().contains(' ') {
            bail!(
                "credential path contains spaces on line {}: {}",
                idx + 1,
                cred_path.display()
            );
        }

        entries.push(DropinEntry {
            name,
            cred_path,
            env_var,
        });
    }

    let mut out = String::new();
    out.push_str("[Service]\n");
    for entry in entries {
        out.push_str(&format!(
            "LoadCredentialEncrypted={}:{}\n",
            entry.name,
            entry.cred_path.display()
        ));
        if !no_env {
            if let Some(env_var) = entry.env_var {
                out.push_str(&format!(
                    "Environment={}=/run/credentials/%N/{}\n",
                    env_var, entry.name
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

    Ok(out)
}
