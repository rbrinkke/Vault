use crate::cli::CliContext;
use crate::core::{metadata, file_lock::FileLock, service_map};
use crate::core::paths::VaultPaths;
use crate::models::credential::CredentialMeta;
use crate::util::{fs as vault_fs, systemd};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, Table};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Subcommand, Debug)]
pub enum MigrateCommand {
    /// Scan a .env file and detect secrets
    Scan(MigrateScanArgs),
    /// Import secrets from .env to credstore
    Import(MigrateImportArgs),
    /// Verify a service runs after migration
    Verify(MigrateVerifyArgs),
}

#[derive(Args, Debug)]
pub struct MigrateScanArgs {
    /// Path to .env file
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct MigrateImportArgs {
    /// Path to .env file
    pub path: PathBuf,

    /// Service name for the map file
    #[arg(long)]
    pub service: String,

    /// Key to use for encryption (host|tpm2|host+tpm2|auto; default: host+tpm2 if TPM2 available)
    #[arg(long)]
    pub with_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct MigrateVerifyArgs {
    /// Service name to verify
    pub service: String,
}

struct EnvEntry {
    key: String,
    value: Zeroizing<String>,
    is_secret: bool,
}

const SECRET_PATTERNS: &[&str] = &[
    "PASSWORD", "TOKEN", "SECRET", "API_KEY", "PRIVATE_KEY",
    "ACCESS_KEY", "CREDENTIAL", "SIGNING_KEY", "ENCRYPTION_KEY",
    "DATABASE_URL", "REDIS_URL", "MONGO_URI", "SMTP_PASS",
    "AWS_SECRET", "STRIPE_KEY", "WEBHOOK_SECRET", "JWT_SECRET",
    "SESSION_SECRET", "MASTER_KEY", "PASSPHRASE", "DSN",
    "CONNECTION_STRING", "AUTH_KEY",
];

pub fn run(ctx: &CliContext, cmd: MigrateCommand) -> Result<()> {
    let paths = &ctx.paths;
    match cmd {
        MigrateCommand::Scan(args) => run_scan(paths, args),
        MigrateCommand::Import(args) => {
            if !ctx.policy.is_service_allowed(&args.service) {
                bail!(
                    "policy: service '{}' not allowed (service_allowlist enforced)",
                    args.service
                );
            }
            run_import(ctx, paths, args)
        }
        MigrateCommand::Verify(args) => run_verify(paths, args),
    }
}

fn run_scan(_paths: &VaultPaths, args: MigrateScanArgs) -> Result<()> {
    if !args.path.is_file() {
        bail!("file not found: {}", args.path.display());
    }

    let entries = parse_env_file(&args.path)?;
    if entries.is_empty() {
        println!("No entries found in {}", args.path.display());
        return Ok(());
    }

    let secret_count = entries.iter().filter(|e| e.is_secret).count();
    let config_count = entries.len() - secret_count;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Key").add_attribute(Attribute::Bold),
        Cell::new("Type").add_attribute(Attribute::Bold),
        Cell::new("Value Preview").add_attribute(Attribute::Bold),
    ]);

    for entry in &entries {
        let type_label = if entry.is_secret {
            Cell::new("SECRET").fg(Color::Red)
        } else {
            Cell::new("config").fg(Color::Green)
        };
        let preview = if entry.is_secret {
            mask_value(&entry.value)
        } else {
            truncate_value(&entry.value, 40)
        };
        table.add_row(vec![
            Cell::new(&entry.key),
            type_label,
            Cell::new(preview),
        ]);
    }

    println!("{}", table);
    println!(
        "\nFound {} secrets, {} config values in {}",
        secret_count,
        config_count,
        args.path.display()
    );
    if secret_count > 0 {
        println!("Run 'goamet-vault migrate import {}' to import secrets to credstore.", args.path.display());
    }

    Ok(())
}

fn run_import(ctx: &CliContext, paths: &VaultPaths, args: MigrateImportArgs) -> Result<()> {
    if !args.path.is_file() {
        bail!("file not found: {}", args.path.display());
    }

    let _vault_lock = FileLock::exclusive(&paths.vault_lock)?;

    let with_key = match args.with_key.as_deref() {
        Some(k) => k.to_string(),
        None => {
            if systemd::has_tpm2().unwrap_or(false) {
                crate::constants::DEFAULT_KEY_TYPE_WITH_TPM2.to_string()
            } else {
                crate::constants::DEFAULT_KEY_TYPE_WITHOUT_TPM2.to_string()
            }
        }
    };

    let entries = parse_env_file(&args.path)?;
    let secrets: Vec<&EnvEntry> = entries.iter().filter(|e| e.is_secret).collect();

    if secrets.is_empty() {
        println!("No secrets detected in {}", args.path.display());
        return Ok(());
    }

    vault_fs::ensure_dir(&paths.credstore, 0o700)?;
    vault_fs::ensure_dir(&paths.services, 0o755)?;

    let mut vault = metadata::load(&paths.vault_toml)?;
    metadata::ensure_vault_section(&mut vault, Some(paths.credstore.display().to_string()));

    let mut map_lines = Vec::new();
    let now = Utc::now();
    let mut imported = 0u32;

    for entry in &secrets {
        let cred_name = entry.key.to_lowercase();
        let cred_path = paths.credstore.join(format!("{}.cred", cred_name));

        // Write secret to temp file in credstore (0700), not /tmp
        let mut tmp = tempfile::Builder::new()
            .prefix(".secret-")
            .tempfile_in(&paths.credstore)
            .context("create temp file")?;
        tmp.write_all(entry.value.as_bytes())
            .context("write temp secret")?;
        tmp.flush().context("flush temp secret")?;

        match systemd::encrypt(&with_key, &cred_name, tmp.path(), &cred_path, None) {
            Ok(()) => {
                vault_fs::set_permissions(&cred_path, 0o600)?;

                let meta = CredentialMeta {
                    name: cred_name.clone(),
                    description: Some(format!("Imported from {}", args.path.display())),
                    created_at: Some(now),
                    rotated_at: Some(now),
                    encryption_key: Some(with_key.clone()),
                    tags: vec!["migrated".to_string()],
                    services: vec![args.service.clone()],
                };
                metadata::upsert_credential(&mut vault, meta);

                // Map line: cred_name ENV_VAR_FILE
                map_lines.push(format!("{} {}_FILE", cred_name, entry.key));

                ctx.audit_simple("import", &cred_name);

                println!("  Imported: {} -> {}", entry.key, cred_path.display());
                imported += 1;
            }
            Err(e) => {
                eprintln!("  Failed to import {}: {}", entry.key, e);
            }
        }
    }

    if imported > 0 {
        metadata::save(&paths.vault_toml, &vault)?;

        // Write service map file atomically
        let map_path = paths.services.join(format!("{}.conf", args.service));
        let map_content = map_lines.join("\n") + "\n";
        let mut tmp = tempfile::Builder::new()
            .prefix(".map-")
            .tempfile_in(&paths.services)
            .context("create temp map file")?;
        tmp.write_all(map_content.as_bytes())
            .context("write temp map")?;
        tmp.flush().context("flush temp map")?;
        tmp.persist(&map_path)
            .map_err(|e| anyhow::anyhow!("persist map file: {}", e))?;

        println!(
            "\nImported {} secrets for service '{}'.",
            imported, args.service
        );
        println!("Service map: {}", map_path.display());
        println!("Run 'goamet-vault dropin generate {}' to create the systemd drop-in.", args.service);
    }

    Ok(())
}

fn run_verify(paths: &VaultPaths, args: MigrateVerifyArgs) -> Result<()> {
    let map_path = paths.services.join(format!("{}.conf", args.service));
    if !map_path.is_file() {
        bail!("service map not found: {}", map_path.display());
    }

    let entries = service_map::parse_service_map(&map_path, &paths.credstore)?;

    let mut passed = 0u32;
    let mut failed = 0u32;

    for entry in &entries {
        let cred_path = if entry.is_custom_path {
            entry.cred_path.clone()
        } else {
            paths.credstore.join(format!("{}.cred", entry.cred_name))
        };

        if !cred_path.is_file() {
            println!("  [FAIL] Missing .cred file: {}", entry.cred_name);
            failed += 1;
            continue;
        }

        // Try to decrypt to verify
        let tmp = tempfile::NamedTempFile::new()?;
        match systemd::decrypt_to_file(&cred_path, tmp.path()) {
            Ok(()) => {
                println!("  [PASS] {}", entry.cred_name);
                passed += 1;
            }
            Err(e) => {
                println!("  [FAIL] Cannot decrypt {}: {}", entry.cred_name, e);
                failed += 1;
            }
        }
    }

    println!();
    if failed == 0 {
        println!("Verify '{}': {} passed, 0 failed", args.service, passed);
    } else {
        println!("Verify '{}': {} passed, {} failed", args.service, passed, failed);
    }

    Ok(())
}

fn parse_env_file(path: &PathBuf) -> Result<Vec<EnvEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;

    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
            let is_secret = detect_secret(&key, &value);
            entries.push(EnvEntry {
                key,
                value: Zeroizing::new(value),
                is_secret,
            });
        }
    }
    Ok(entries)
}

fn detect_secret(key: &str, value: &str) -> bool {
    let upper = key.to_uppercase();
    for pattern in SECRET_PATTERNS {
        if upper.contains(pattern) {
            return true;
        }
    }
    // URL with embedded credentials (contains :// and @)
    if value.contains("://") && value.contains('@') {
        return true;
    }
    // Base64-like strings >20 chars
    if value.len() > 20
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return true;
    }
    // Hex strings >32 chars
    if value.len() > 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

fn mask_value(value: &str) -> String {
    if value.len() <= 4 {
        "*".repeat(value.len())
    } else {
        format!("{}...{}", &value[..2], &value[value.len() - 2..])
    }
}

fn truncate_value(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}...", &value[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_secret_by_name() {
        assert!(detect_secret("DB_PASSWORD", "value"));
        assert!(detect_secret("API_TOKEN", "value"));
        assert!(detect_secret("MY_SECRET", "value"));
    }

    #[test]
    fn test_detect_secret_config_values() {
        assert!(!detect_secret("APP_NAME", "myapp"));
        assert!(!detect_secret("PORT", "8080"));
        assert!(!detect_secret("DEBUG", "true"));
    }

    #[test]
    fn test_detect_secret_url_with_password() {
        assert!(detect_secret("DATABASE_URL", "postgres://user:pass@host/db"));
    }

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("abcdef"), "ab...ef");
        assert_eq!(mask_value("ab"), "**");
    }

    #[test]
    fn test_truncate_value() {
        assert_eq!(truncate_value("short", 40), "short");
        let long = "a".repeat(50);
        let result = truncate_value(&long, 10);
        assert!(result.ends_with("..."));
        assert_eq!(result.len(), 10);
    }
}
