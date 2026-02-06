//! Dry-run preview of mutating operations.

use crate::cli::CliContext;
use crate::constants;
use crate::core::service_map;
use crate::util::systemd;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum PlanCommand {
    /// Preview a credential rotation
    Rotate(PlanRotateArgs),
    /// Preview a drop-in apply
    Dropin(PlanDropinArgs),
    /// Preview a migration import
    Migrate(PlanMigrateArgs),
}

#[derive(Args, Debug)]
pub struct PlanRotateArgs {
    /// Credential name
    pub name: String,
    /// Auto-generate secret
    #[arg(long)]
    pub auto: bool,
    /// Secret length
    #[arg(long, default_value_t = 32)]
    pub length: usize,
    /// Output format (text|json)
    #[arg(long, default_value = "text")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct PlanDropinArgs {
    /// Service name
    pub service: String,
    /// Map file override
    #[arg(long, value_name = "PATH")]
    pub map_file: Option<PathBuf>,
    /// Output format (text|json)
    #[arg(long, default_value = "text")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct PlanMigrateArgs {
    /// Path to .env file
    pub path: PathBuf,
    /// Service name
    #[arg(long)]
    pub service: String,
    /// Output format (text|json)
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(ctx: &CliContext, cmd: PlanCommand) -> Result<()> {
    match cmd {
        PlanCommand::Rotate(args) => plan_rotate(ctx, args),
        PlanCommand::Dropin(args) => plan_dropin(ctx, args),
        PlanCommand::Migrate(args) => plan_migrate(ctx, args),
    }
}

fn plan_rotate(ctx: &CliContext, args: PlanRotateArgs) -> Result<()> {
    let paths = &ctx.paths;
    let cred_path = paths.credstore.join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    let exists = cred_path.is_file();

    // Check preconditions
    let mut issues: Vec<String> = Vec::new();
    if !exists {
        issues.push(format!("credential '{}' does not exist (will create new)", args.name));
    }
    if !paths.credstore.is_dir() {
        issues.push("credstore directory missing".to_string());
    }

    // Policy checks
    if args.auto {
        if let Some(min_len) = ctx.policy.min_auto_secret_length {
            if args.length < min_len {
                issues.push(format!(
                    "auto length {} below policy minimum {}",
                    args.length, min_len
                ));
            }
        }
    }

    let key_type = if systemd::has_tpm2().unwrap_or(false) {
        constants::DEFAULT_KEY_TYPE_WITH_TPM2
    } else {
        constants::DEFAULT_KEY_TYPE_WITHOUT_TPM2
    };

    if args.format == "json" {
        let plan = serde_json::json!({
            "action": "rotate",
            "credential": args.name,
            "exists": exists,
            "auto": args.auto,
            "length": if args.auto { Some(args.length) } else { None },
            "key_type": key_type,
            "issues": issues,
        });
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("Plan: rotate '{}'", args.name);
        println!("  exists: {}", exists);
        println!("  key_type: {}", key_type);
        if args.auto {
            println!("  auto: length={}", args.length);
        } else {
            println!("  source: stdin/prompt");
        }
        if issues.is_empty() {
            println!("  status: ready");
        } else {
            for issue in &issues {
                println!("  issue: {}", issue);
            }
        }
        println!("\nNo changes made (dry-run).");
    }

    Ok(())
}

fn plan_dropin(ctx: &CliContext, args: PlanDropinArgs) -> Result<()> {
    let paths = &ctx.paths;
    let map_name = args.service.strip_suffix(".service").unwrap_or(&args.service);
    let unit_name = if args.service.ends_with(".service") {
        args.service.clone()
    } else {
        format!("{}.service", args.service)
    };

    let map_file = args
        .map_file
        .unwrap_or_else(|| paths.services.join(format!("{}.conf", map_name)));

    if !map_file.is_file() {
        bail!("map file not found: {}", map_file.display());
    }

    let entries = service_map::parse_service_map(&map_file, &paths.credstore)?;
    let out_dir = paths.units.join(format!("{}.d", unit_name));
    let target_file = out_dir.join("credentials.conf");
    let installed = PathBuf::from(format!(
        "/etc/systemd/system/{}.d/credentials.conf",
        unit_name
    ));

    if args.format == "json" {
        let creds: Vec<_> = entries.iter().map(|e| &e.cred_name).collect();
        let plan = serde_json::json!({
            "action": "dropin apply",
            "service": args.service,
            "credentials": creds,
            "local_path": target_file.display().to_string(),
            "install_path": installed.display().to_string(),
            "installed_exists": installed.is_file(),
        });
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("Plan: dropin apply '{}'", args.service);
        println!("  map file: {}", map_file.display());
        println!("  credentials: {}", entries.len());
        for entry in &entries {
            println!("    - {}", entry.cred_name);
        }
        println!("  local: {}", target_file.display());
        println!("  install: {}", installed.display());
        println!(
            "  currently installed: {}",
            if installed.is_file() { "yes" } else { "no" }
        );
        println!("\nNo changes made (dry-run).");
    }

    Ok(())
}

fn plan_migrate(ctx: &CliContext, args: PlanMigrateArgs) -> Result<()> {
    if !args.path.is_file() {
        bail!("file not found: {}", args.path.display());
    }

    let content = std::fs::read_to_string(&args.path)?;
    let mut secrets = Vec::new();
    let mut configs = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim().to_string();
            let upper = key.to_uppercase();
            let is_secret = ["PASSWORD", "TOKEN", "SECRET", "API_KEY", "PRIVATE_KEY"]
                .iter()
                .any(|p| upper.contains(p));
            if is_secret {
                secrets.push(key);
            } else {
                configs.push(key);
            }
        }
    }

    let map_path = ctx.paths.services.join(format!("{}.conf", args.service));

    if args.format == "json" {
        let plan = serde_json::json!({
            "action": "migrate import",
            "source": args.path.display().to_string(),
            "service": args.service,
            "secrets_detected": secrets,
            "config_values": configs.len(),
            "map_file": map_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("Plan: migrate import from '{}'", args.path.display());
        println!("  service: {}", args.service);
        println!("  secrets detected: {}", secrets.len());
        for s in &secrets {
            println!("    - {}", s);
        }
        println!("  config values skipped: {}", configs.len());
        println!("  map file: {}", map_path.display());
        println!("\nNo changes made (dry-run).");
    }

    Ok(())
}
