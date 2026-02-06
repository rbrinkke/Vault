use crate::cli::CliContext;
use crate::constants;
use crate::core::{credstore, file_lock::FileLock, metadata};
use crate::models::credential::CredentialMeta;
use crate::models::policy::PolicySection;
use crate::util::{fs as vault_fs, systemd};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Table};
use dialoguer::Password;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::{self, NamedTempFile};
use zeroize::Zeroizing;

fn parse_credential_name(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("name cannot be empty".into());
    }
    if s.contains("..") {
        return Err("path traversal not allowed".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err("only [a-zA-Z0-9._-] allowed".into());
    }
    Ok(s.to_string())
}

fn parse_with_key(s: &str) -> Result<String, String> {
    if constants::VALID_KEY_TYPES.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "invalid key type '{}', must be one of: {}",
            s,
            constants::VALID_KEY_TYPES.join(", ")
        ))
    }
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,

    /// Key to use for encryption (host|tpm2|host+tpm2|auto; default: host+tpm2 if TPM2 available)
    #[arg(long, value_parser = parse_with_key)]
    pub with_key: Option<String>,

    /// TPM2 PCR values to bind to (advanced, e.g. "7" or "7+11")
    #[arg(long, value_name = "PCRS")]
    pub tpm2_pcrs: Option<String>,

    /// Read secret from stdin instead of interactive prompt
    #[arg(long)]
    pub from_stdin: bool,

    /// Description stored in metadata
    #[arg(long)]
    pub description: Option<String>,

    /// Tag(s) for metadata
    #[arg(long, value_name = "TAG")]
    pub tag: Vec<String>,

    /// Service(s) linked to this credential
    #[arg(long, value_name = "SERVICE")]
    pub service: Vec<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,

    /// Output file (avoid stdout)
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Allow stdout output (dangerous)
    #[arg(long)]
    pub confirm: bool,

    /// Reason for stdout output (logged)
    #[arg(long)]
    pub reason: Option<String>,

    /// Newline behavior for stdout (auto|yes|no)
    #[arg(long, default_value = "no")]
    pub newline: String,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by service name
    #[arg(long)]
    pub service: Option<String>,

    /// Filter by tag
    #[arg(long)]
    pub tag: Option<String>,

    /// Output format: table|json
    #[arg(long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct DescribeArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Query string
    pub query: String,
}

#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,

    /// Key to use for encryption (host|tpm2|host+tpm2|auto; default: host+tpm2 if TPM2 available)
    #[arg(long, value_parser = parse_with_key)]
    pub with_key: Option<String>,

    /// TPM2 PCR values to bind to (advanced, e.g. "7" or "7+11")
    #[arg(long, value_name = "PCRS")]
    pub tpm2_pcrs: Option<String>,

    /// Read secret from stdin instead of interactive prompt
    #[arg(long)]
    pub from_stdin: bool,

    /// Auto-generate a random secret
    #[arg(long)]
    pub auto: bool,

    /// Length for auto-generated secret
    #[arg(long, default_value_t = 32)]
    pub length: usize,

    /// Description update in metadata
    #[arg(long)]
    pub description: Option<String>,

    /// Tag(s) to replace metadata tags
    #[arg(long, value_name = "TAG")]
    pub tag: Vec<String>,

    /// Service(s) to replace metadata services
    #[arg(long, value_name = "SERVICE")]
    pub service: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum RollbackCommand {
    /// Rollback a rotated credential to its previous version
    Rotate(RollbackRotateArgs),
}

#[derive(Args, Debug)]
pub struct RollbackRotateArgs {
    /// Credential name
    #[arg(value_parser = parse_credential_name)]
    pub name: String,
}

#[derive(Serialize)]
struct ListItem {
    name: String,
    description: Option<String>,
    tags: Vec<String>,
    services: Vec<String>,
    size_bytes: Option<u64>,
    modified: Option<String>,
}

/// Check key-type policy: forbid host-only when TPM2 is available.
fn check_key_policy(policy: &PolicySection, with_key: &str) -> Result<()> {
    if policy.forbid_host_only_when_tpm2
        && with_key == "host"
        && systemd::has_tpm2().unwrap_or(false)
    {
        bail!("policy: host-only encryption forbidden when TPM2 is available (use host+tpm2)");
    }
    Ok(())
}

pub fn run_create(ctx: &CliContext, args: CreateArgs) -> Result<()> {
    let paths = &ctx.paths;
    vault_fs::ensure_dir(&paths.credstore, constants::CREDSTORE_DIR_MODE)?;

    let with_key = resolve_key_type(args.with_key.as_deref());
    check_key_policy(&ctx.policy, &with_key)?;

    // Policy: service allowlist (for metadata linkage)
    if !args.service.is_empty() {
        for svc in &args.service {
            if !ctx.policy.is_service_allowed(svc) {
                bail!(
                    "policy: service '{}' not allowed (service_allowlist enforced)",
                    svc
                );
            }
        }
    }

    // Non-interactive mode requires --from-stdin
    if ctx.non_interactive && !args.from_stdin {
        bail!("--non-interactive requires --from-stdin for create");
    }

    let secret = read_secret(args.from_stdin, &args.name)?;

    let tmp = write_temp_secret(&secret, &paths.credstore)?;

    let output = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    systemd::encrypt(&with_key, &args.name, tmp.path(), &output, args.tpm2_pcrs.as_deref())?;
    vault_fs::set_permissions(&output, constants::CRED_FILE_MODE)?;

    let _vault_lock = FileLock::exclusive(&paths.vault_lock)?;
    let mut vault = metadata::load(&paths.vault_toml)?;
    metadata::ensure_vault_section(&mut vault, Some(paths.credstore.display().to_string()));
    let now = Utc::now();
    let mut meta = vault
        .credentials
        .iter()
        .find(|c| c.name == args.name)
        .cloned()
        .unwrap_or_default();
    if meta.name.is_empty() {
        meta.name = args.name.clone();
    }
    if meta.created_at.is_none() {
        meta.created_at = Some(now);
    }
    meta.rotated_at = Some(now);
    meta.encryption_key = Some(with_key);
    if let Some(desc) = args.description {
        meta.description = Some(desc);
    }
    if !args.tag.is_empty() {
        meta.tags = dedup(args.tag);
    }
    if !args.service.is_empty() {
        meta.services = dedup(args.service);
    }
    metadata::upsert_credential(&mut vault, meta);
    metadata::save(&paths.vault_toml, &vault)?;
    ctx.audit_simple("create", &args.name);

    println!("Wrote {}", output.display());
    Ok(())
}

pub fn run_get(ctx: &CliContext, args: GetArgs) -> Result<()> {
    let paths = &ctx.paths;
    let cred_path = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    if !cred_path.is_file() {
        bail!("credential not found: {}", cred_path.display());
    }

    ctx.audit_simple("get", &args.name);

    if let Some(output) = args.output {
        systemd::decrypt_to_file(&cred_path, &output)?;
        vault_fs::set_permissions(&output, constants::CRED_FILE_MODE)?;
        println!("Wrote {}", output.display());
        return Ok(());
    }

    if !args.confirm {
        bail!("refusing to print secret to stdout without --confirm");
    }
    if args.reason.as_deref().unwrap_or("").trim().is_empty() {
        bail!("--reason is required when printing to stdout");
    }

    let data = systemd::decrypt_to_stdout(&cred_path, Some(args.newline.as_str()))?;
    let mut stdout = std::io::stdout();
    stdout.write_all(&data).context("write to stdout")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

pub fn run_list(ctx: &CliContext, args: ListArgs) -> Result<()> {
    let paths = &ctx.paths;
    if args.format != "table" && args.format != "json" {
        bail!("invalid format: {} (use table|json)", args.format);
    }

    let mut items = Vec::new();

    if paths.vault_toml.exists() {
        let vault = metadata::load(&paths.vault_toml)?;
        for meta in vault.credentials {
            if let Some(service) = &args.service {
                if !meta.services.iter().any(|s| s == service) {
                    continue;
                }
            }
            if let Some(tag) = &args.tag {
                if !meta.tags.iter().any(|t| t == tag) {
                    continue;
                }
            }
            let cred_path = paths.credstore.join(format!("{}{}", meta.name, constants::CRED_EXTENSION));
            let (size_bytes, modified) = if cred_path.is_file() {
                let meta_fs = fs::metadata(&cred_path).ok();
                let size = meta_fs.as_ref().map(|m| m.len());
                let mod_time = meta_fs.and_then(|m| m.modified().ok()).map(|t| {
                    let dt: DateTime<Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                });
                (size, mod_time)
            } else {
                (None, None)
            };

            items.push(ListItem {
                name: meta.name,
                description: meta.description,
                tags: meta.tags,
                services: meta.services,
                size_bytes,
                modified,
            });
        }
    } else if paths.credstore.is_dir() {
        let entries = credstore::list_credentials(&paths.credstore)?;
        for entry in entries {
            let modified = entry.modified.map(|t| {
                let dt: DateTime<Local> = t.into();
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            });
            items.push(ListItem {
                name: entry.name,
                description: None,
                tags: Vec::new(),
                services: Vec::new(),
                size_bytes: Some(entry.size_bytes),
                modified,
            });
        }
    }

    if args.format == "json" {
        let json = serde_json::to_string_pretty(&items).context("serialize list")?;
        println!("{}", json);
        return Ok(());
    }

    if items.is_empty() {
        println!("No credentials found");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Name").add_attribute(Attribute::Bold),
        Cell::new("Description").add_attribute(Attribute::Bold),
        Cell::new("Tags").add_attribute(Attribute::Bold),
        Cell::new("Services").add_attribute(Attribute::Bold),
        Cell::new("Size").add_attribute(Attribute::Bold),
        Cell::new("Modified").add_attribute(Attribute::Bold),
    ]);

    for item in items {
        let tags = if item.tags.is_empty() {
            "-".to_string()
        } else {
            item.tags.join(",")
        };
        let services = if item.services.is_empty() {
            "-".to_string()
        } else {
            item.services.join(",")
        };
        let size = item
            .size_bytes
            .map(|s| format!("{} B", s))
            .unwrap_or_else(|| "-".to_string());
        let modified = item.modified.unwrap_or_else(|| "-".to_string());
        table.add_row(vec![
            item.name,
            item.description.unwrap_or_else(|| "-".to_string()),
            tags,
            services,
            size,
            modified,
        ]);
    }

    println!("{}", table);
    Ok(())
}

pub fn run_delete(ctx: &CliContext, args: DeleteArgs) -> Result<()> {
    let paths = &ctx.paths;
    let cred_path = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    if !cred_path.exists() {
        bail!("credential not found: {}", cred_path.display());
    }

    let _vault_lock = FileLock::exclusive(&paths.vault_lock)?;
    fs::remove_file(&cred_path)
        .with_context(|| format!("remove {}", cred_path.display()))?;
    ctx.audit_simple("delete", &args.name);

    if paths.vault_toml.exists() {
        let mut vault = metadata::load(&paths.vault_toml)?;
        metadata::remove_credential(&mut vault, &args.name);
        metadata::save(&paths.vault_toml, &vault)?;
    }

    println!("Deleted {}", cred_path.display());
    Ok(())
}

pub fn run_describe(ctx: &CliContext, args: DescribeArgs) -> Result<()> {
    let paths = &ctx.paths;
    if !paths.vault_toml.exists() {
        bail!("metadata not found: {}", paths.vault_toml.display());
    }
    let vault = metadata::load(&paths.vault_toml)?;
    let meta = vault
        .credentials
        .iter()
        .find(|c| c.name == args.name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("metadata not found for {}", args.name))?;

    println!("name: {}", meta.name);
    if let Some(desc) = meta.description {
        println!("description: {}", desc);
    }
    if let Some(created) = meta.created_at {
        println!("created_at: {}", created.to_rfc3339());
    }
    if let Some(rotated) = meta.rotated_at {
        println!("rotated_at: {}", rotated.to_rfc3339());
    }
    if let Some(key) = meta.encryption_key {
        println!("encryption_key: {}", key);
    }
    if !meta.tags.is_empty() {
        println!("tags: {}", meta.tags.join(","));
    }
    if !meta.services.is_empty() {
        println!("services: {}", meta.services.join(","));
    }
    Ok(())
}

pub fn run_search(ctx: &CliContext, args: SearchArgs) -> Result<()> {
    let paths = &ctx.paths;
    if !paths.vault_toml.exists() {
        bail!("metadata not found: {}", paths.vault_toml.display());
    }
    let vault = metadata::load(&paths.vault_toml)?;
    let q = args.query.to_lowercase();
    let matches: Vec<_> = vault
        .credentials
        .into_iter()
        .filter(|c| match_credential(c, &q))
        .collect();

    if matches.is_empty() {
        println!("No matches for '{}'.", args.query);
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Name").add_attribute(Attribute::Bold),
        Cell::new("Description").add_attribute(Attribute::Bold),
        Cell::new("Tags").add_attribute(Attribute::Bold),
        Cell::new("Services").add_attribute(Attribute::Bold),
    ]);

    for meta in matches {
        let tags = if meta.tags.is_empty() {
            "-".to_string()
        } else {
            meta.tags.join(",")
        };
        let services = if meta.services.is_empty() {
            "-".to_string()
        } else {
            meta.services.join(",")
        };
        table.add_row(vec![
            meta.name,
            meta.description.unwrap_or_else(|| "-".to_string()),
            tags,
            services,
        ]);
    }

    println!("{}", table);
    Ok(())
}

pub fn run_rotate(ctx: &CliContext, args: RotateArgs) -> Result<()> {
    let paths = &ctx.paths;
    vault_fs::ensure_dir(&paths.credstore, constants::CREDSTORE_DIR_MODE)?;

    let with_key = resolve_key_type(args.with_key.as_deref());
    check_key_policy(&ctx.policy, &with_key)?;

    // Policy: service allowlist (for metadata linkage)
    if !args.service.is_empty() {
        for svc in &args.service {
            if !ctx.policy.is_service_allowed(svc) {
                bail!(
                    "policy: service '{}' not allowed (service_allowlist enforced)",
                    svc
                );
            }
        }
    }

    if args.auto && args.from_stdin {
        bail!("--auto and --from-stdin cannot be used together");
    }

    // Non-interactive mode requires --from-stdin or --auto
    if ctx.non_interactive && !args.from_stdin && !args.auto {
        bail!("--non-interactive requires --from-stdin or --auto for rotate");
    }

    // Policy: minimum auto-secret length
    if args.auto {
        if let Some(min_len) = ctx.policy.min_auto_secret_length {
            if args.length < min_len {
                bail!(
                    "policy: auto-generated secret length {} below minimum {} (set in vault.toml [policy])",
                    args.length,
                    min_len
                );
            }
        }
    }

    let secret: Zeroizing<String> = if args.auto {
        Zeroizing::new(generate_secret(args.length))
    } else {
        read_secret(args.from_stdin, &args.name)?
    };

    if secret.is_empty() {
        bail!("secret is empty");
    }

    let tmp_secret = write_temp_secret(&secret, &paths.credstore)?;
    let tmp_output = tempfile::Builder::new()
        .prefix("cred-")
        .suffix(".cred.tmp")
        .tempfile_in(&paths.credstore)
        .context("create temp output")?;
    systemd::encrypt(&with_key, &args.name, tmp_secret.path(), tmp_output.path(), args.tpm2_pcrs.as_deref())?;

    let _vault_lock = FileLock::exclusive(&paths.vault_lock)?;
    let final_path = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));

    // Create .prev backup before overwriting
    let prev_path = paths.credstore.join(format!("{}{}.prev", args.name, constants::CRED_EXTENSION));
    if final_path.is_file() {
        fs::copy(&final_path, &prev_path)
            .with_context(|| format!("backup {} to .prev", final_path.display()))?;
    }

    match tmp_output.persist(&final_path) {
        Ok(_) => {}
        Err(e) => {
            // Restore from backup on failure
            if prev_path.is_file() {
                let _ = fs::rename(&prev_path, &final_path);
            }
            bail!("persist rotated credential: {}", e);
        }
    }
    vault_fs::set_permissions(&final_path, constants::CRED_FILE_MODE)?;

    let mut vault = metadata::load(&paths.vault_toml)?;
    metadata::ensure_vault_section(&mut vault, Some(paths.credstore.display().to_string()));
    let now = Utc::now();
    let mut meta = vault
        .credentials
        .iter()
        .find(|c| c.name == args.name)
        .cloned()
        .unwrap_or_default();
    if meta.name.is_empty() {
        meta.name = args.name.clone();
    }
    if meta.created_at.is_none() {
        meta.created_at = Some(now);
    }
    meta.rotated_at = Some(now);
    meta.encryption_key = Some(with_key);
    if let Some(desc) = args.description {
        meta.description = Some(desc);
    }
    if !args.tag.is_empty() {
        meta.tags = dedup(args.tag);
    }
    if !args.service.is_empty() {
        meta.services = dedup(args.service);
    }
    metadata::upsert_credential(&mut vault, meta);
    metadata::save(&paths.vault_toml, &vault)?;
    ctx.audit_simple("rotate", &args.name);

    println!("Rotated {}", final_path.display());
    Ok(())
}

pub fn run_rollback(ctx: &CliContext, cmd: RollbackCommand) -> Result<()> {
    match cmd {
        RollbackCommand::Rotate(args) => run_rollback_rotate(ctx, args),
    }
}

fn run_rollback_rotate(ctx: &CliContext, args: RollbackRotateArgs) -> Result<()> {
    let paths = &ctx.paths;
    let _vault_lock = FileLock::exclusive(&paths.vault_lock)?;
    let cred_path = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    let prev_path = paths.credstore.join(format!("{}{}.prev", args.name, constants::CRED_EXTENSION));

    if !prev_path.is_file() {
        bail!("no .prev backup found for '{}' — cannot rollback", args.name);
    }

    fs::rename(&prev_path, &cred_path)
        .with_context(|| format!("restore {} from .prev", args.name))?;

    ctx.audit_simple("rollback-rotate", &args.name);
    println!("Rolled back '{}' to previous version", args.name);
    Ok(())
}

#[cfg(test)]
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("name cannot be empty");
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        bail!("invalid name: path separators are not allowed");
    }
    if name.chars().any(|c| c.is_whitespace()) {
        bail!("invalid name: whitespace not allowed");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        bail!("invalid name: only [a-zA-Z0-9._-] allowed");
    }
    Ok(())
}

/// Resolve the effective key type: use explicit value or auto-detect TPM2.
fn resolve_key_type(explicit: Option<&str>) -> String {
    match explicit {
        Some(k) => k.to_string(),
        None => {
            if systemd::has_tpm2().unwrap_or(false) {
                constants::DEFAULT_KEY_TYPE_WITH_TPM2.to_string()
            } else {
                constants::DEFAULT_KEY_TYPE_WITHOUT_TPM2.to_string()
            }
        }
    }
}

fn read_secret(from_stdin: bool, name: &str) -> Result<Zeroizing<String>> {
    let secret = if from_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read secret from stdin")?;
        Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string())
    } else {
        Zeroizing::new(
            Password::new()
                .with_prompt(format!("Secret for {}", name))
                .allow_empty_password(false)
                .interact()
                .context("read secret from prompt")?,
        )
    };
    if secret.len() > constants::MAX_SECRET_SIZE {
        bail!(
            "secret exceeds maximum size ({} bytes, max {} bytes)",
            secret.len(),
            constants::MAX_SECRET_SIZE
        );
    }
    Ok(secret)
}

fn write_temp_secret(secret: &str, credstore: &Path) -> Result<NamedTempFile> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".secret-")
        .tempfile_in(credstore)
        .context("create temp file")?;
    tmp.write_all(secret.as_bytes())
        .context("write temp secret")?;
    tmp.flush().context("flush temp secret")?;
    Ok(tmp)
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|v| seen.insert(v.clone()))
        .collect()
}

fn match_credential(meta: &CredentialMeta, query: &str) -> bool {
    if meta.name.to_lowercase().contains(query) {
        return true;
    }
    if let Some(desc) = &meta.description {
        if desc.to_lowercase().contains(query) {
            return true;
        }
    }
    if meta
        .tags
        .iter()
        .any(|t| t.to_lowercase().contains(query))
    {
        return true;
    }
    if meta
        .services
        .iter()
        .any(|s| s.to_lowercase().contains(query))
    {
        return true;
    }
    false
}

fn generate_secret(length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    OsRng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("db_password").is_ok());
        assert!(validate_name("api.token").is_ok());
        assert!(validate_name("my-secret-123").is_ok());
    }

    #[test]
    fn test_validate_name_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn test_validate_name_path_separators() {
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("foo\\bar").is_err());
    }

    #[test]
    fn test_validate_name_whitespace() {
        assert!(validate_name("foo bar").is_err());
        assert!(validate_name("foo\tbar").is_err());
    }

    #[test]
    fn test_validate_name_special_chars() {
        assert!(validate_name("foo@bar").is_err());
        assert!(validate_name("foo$bar").is_err());
        assert!(validate_name("foo!bar").is_err());
    }

    #[test]
    fn test_dedup_preserves_order() {
        let input = vec!["b".into(), "a".into(), "b".into(), "c".into()];
        assert_eq!(dedup(input), vec!["b", "a", "c"]);
    }

    #[test]
    fn test_dedup_empty() {
        let input: Vec<String> = vec![];
        assert_eq!(dedup(input), Vec::<String>::new());
    }

    #[test]
    fn test_match_credential_by_name() {
        let meta = CredentialMeta {
            name: "db_password".into(),
            ..Default::default()
        };
        assert!(match_credential(&meta, "db_pass"));
    }

    #[test]
    fn test_match_credential_by_tag() {
        let meta = CredentialMeta {
            name: "x".into(),
            tags: vec!["test".into()],
            ..Default::default()
        };
        assert!(match_credential(&meta, "test"));
    }

    #[test]
    fn test_match_credential_case_insensitive() {
        let meta = CredentialMeta {
            name: "DB_Password".into(),
            ..Default::default()
        };
        assert!(match_credential(&meta, "db_password"));
    }

    #[test]
    fn test_generate_secret_length() {
        assert_eq!(generate_secret(32).len(), 32);
        assert_eq!(generate_secret(0).len(), 0);
        assert_eq!(generate_secret(1).len(), 1);
    }

    #[test]
    fn test_generate_secret_alphanumeric() {
        let s = generate_secret(100);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
