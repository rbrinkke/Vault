use crate::core::{credstore, metadata};
use crate::core::paths::VaultPaths;
use crate::models::credential::CredentialMeta;
use crate::util::{fs as vault_fs, systemd};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Args;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Table};
use dialoguer::Password;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Credential name
    pub name: String,

    /// Key to use for encryption (host|tpm2|host+tpm2|auto)
    #[arg(long, default_value = "host")]
    pub with_key: String,

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
    pub name: String,
}

#[derive(Args, Debug)]
pub struct DescribeArgs {
    /// Credential name
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
    pub name: String,

    /// Key to use for encryption (host|tpm2|host+tpm2|auto)
    #[arg(long, default_value = "host")]
    pub with_key: String,

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

#[derive(Serialize)]
struct ListItem {
    name: String,
    description: Option<String>,
    tags: Vec<String>,
    services: Vec<String>,
    size_bytes: Option<u64>,
    modified: Option<String>,
}

pub fn run_create(paths: &VaultPaths, args: CreateArgs) -> Result<()> {
    validate_name(&args.name)?;
    vault_fs::ensure_dir(&paths.credstore, 0o700)?;

    let secret = read_secret(args.from_stdin, &args.name)?;

    let mut tmp = NamedTempFile::new().context("create temp file")?;
    tmp.write_all(secret.as_bytes())
        .context("write temp secret")?;
    tmp.flush().ok();

    let output = paths.credstore.join(format!("{}.cred", args.name));
    systemd::encrypt(&args.with_key, &args.name, tmp.path(), &output)?;
    vault_fs::set_permissions(&output, 0o600)?;

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
    meta.encryption_key = Some(args.with_key.clone());
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

    println!("Wrote {}", output.display());
    Ok(())
}

pub fn run_get(paths: &VaultPaths, args: GetArgs) -> Result<()> {
    validate_name(&args.name)?;
    let cred_path = paths.credstore.join(format!("{}.cred", args.name));
    if !cred_path.is_file() {
        bail!("credential not found: {}", cred_path.display());
    }

    if let Some(output) = args.output {
        systemd::decrypt_to_file(&cred_path, &output)?;
        vault_fs::set_permissions(&output, 0o600).ok();
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
    stdout.flush().ok();
    Ok(())
}

pub fn run_list(paths: &VaultPaths, args: ListArgs) -> Result<()> {
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
            let cred_path = paths.credstore.join(format!("{}.cred", meta.name));
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

pub fn run_delete(paths: &VaultPaths, args: DeleteArgs) -> Result<()> {
    validate_name(&args.name)?;
    let cred_path = paths.credstore.join(format!("{}.cred", args.name));
    if !cred_path.exists() {
        bail!("credential not found: {}", cred_path.display());
    }
    fs::remove_file(&cred_path)
        .with_context(|| format!("remove {}", cred_path.display()))?;

    if paths.vault_toml.exists() {
        let mut vault = metadata::load(&paths.vault_toml)?;
        metadata::remove_credential(&mut vault, &args.name);
        metadata::save(&paths.vault_toml, &vault)?;
    }

    println!("Deleted {}", cred_path.display());
    Ok(())
}

pub fn run_describe(paths: &VaultPaths, args: DescribeArgs) -> Result<()> {
    validate_name(&args.name)?;
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

pub fn run_search(paths: &VaultPaths, args: SearchArgs) -> Result<()> {
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

pub fn run_rotate(paths: &VaultPaths, args: RotateArgs) -> Result<()> {
    validate_name(&args.name)?;
    vault_fs::ensure_dir(&paths.credstore, 0o700)?;

    if args.auto && args.from_stdin {
        bail!("--auto and --from-stdin cannot be used together");
    }

    let secret = if args.auto {
        generate_secret(args.length)
    } else {
        read_secret(args.from_stdin, &args.name)?
    };

    if secret.is_empty() {
        bail!("secret is empty");
    }

    let tmp_output = temp_output_path(&paths.credstore)?;
    let tmp_secret = write_temp_secret(&secret)?;
    systemd::encrypt(&args.with_key, &args.name, tmp_secret.path(), &tmp_output)?;

    let final_path = paths.credstore.join(format!("{}.cred", args.name));
    fs::rename(&tmp_output, &final_path)
        .with_context(|| format!("replace {}", final_path.display()))?;
    vault_fs::set_permissions(&final_path, 0o600)?;

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
    meta.encryption_key = Some(args.with_key.clone());
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

    println!("Rotated {}", final_path.display());
    Ok(())
}

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

fn read_secret(from_stdin: bool, name: &str) -> Result<String> {
    if from_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read secret from stdin")?;
        return Ok(buf.trim_end_matches(['\r', '\n']).to_string());
    }

    let secret = Password::new()
        .with_prompt(format!("Secret for {}", name))
        .allow_empty_password(false)
        .interact()
        .context("read secret from prompt")?;
    Ok(secret)
}

fn write_temp_secret(secret: &str) -> Result<NamedTempFile> {
    let mut tmp = NamedTempFile::new().context("create temp file")?;
    tmp.write_all(secret.as_bytes())
        .context("write temp secret")?;
    tmp.flush().ok();
    Ok(tmp)
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for val in values {
        if !out.contains(&val) {
            out.push(val);
        }
    }
    out
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

fn temp_output_path(dir: &Path) -> Result<PathBuf> {
    let tmp = tempfile::Builder::new()
        .prefix("cred-")
        .suffix(".cred.tmp")
        .tempfile_in(dir)
        .context("create temp output")?;
    let path = tmp.path().to_path_buf();
    drop(tmp);
    if path.exists() {
        fs::remove_file(&path).ok();
    }
    Ok(path)
}
