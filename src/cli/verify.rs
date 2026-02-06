//! Post-operation verification commands.

use crate::cli::CliContext;
use crate::constants;
use crate::core::{metadata, service_map};
use crate::util::systemd;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum VerifyCommand {
    /// Verify a rotated credential is decryptable and metadata is consistent
    Rotate(VerifyRotateArgs),
    /// Verify a drop-in matches the service map
    Dropin(VerifyDropinArgs),
    /// Verify all credentials and service maps
    All(VerifyAllArgs),
}

#[derive(Args, Debug)]
pub struct VerifyRotateArgs {
    /// Credential name
    pub name: String,
}

#[derive(Args, Debug)]
pub struct VerifyDropinArgs {
    /// Service name
    pub service: String,
}

#[derive(Args, Debug)]
pub struct VerifyAllArgs {}

pub fn run(ctx: &CliContext, cmd: VerifyCommand) -> Result<()> {
    match cmd {
        VerifyCommand::Rotate(args) => verify_rotate(ctx, args),
        VerifyCommand::Dropin(args) => verify_dropin(ctx, args),
        VerifyCommand::All(_) => verify_all(ctx),
    }
}

fn verify_rotate(ctx: &CliContext, args: VerifyRotateArgs) -> Result<()> {
    let paths = &ctx.paths;
    let cred_path = paths
        .credstore
        .join(format!("{}{}", args.name, constants::CRED_EXTENSION));
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Check .cred file exists
    if cred_path.is_file() {
        println!("  [PASS] .cred file exists: {}", args.name);
        passed += 1;
    } else {
        println!("  [FAIL] .cred file missing: {}", args.name);
        failed += 1;
    }

    // Try decrypt
    if cred_path.is_file() {
        let tmp = tempfile::NamedTempFile::new()?;
        match systemd::decrypt_to_file(&cred_path, tmp.path()) {
            Ok(()) => {
                println!("  [PASS] Decryptable: {}", args.name);
                passed += 1;
            }
            Err(e) => {
                println!("  [FAIL] Cannot decrypt: {} ({})", args.name, e);
                failed += 1;
            }
        }
    }

    // Check metadata
    if paths.vault_toml.exists() {
        let vault = metadata::load(&paths.vault_toml)?;
        if vault.credentials.iter().any(|c| c.name == args.name) {
            println!("  [PASS] Metadata present in vault.toml");
            passed += 1;
        } else {
            println!("  [FAIL] Metadata missing from vault.toml");
            failed += 1;
        }
    }

    println!();
    if failed == 0 {
        println!("Verify rotate '{}': {} passed, 0 failed", args.name, passed);
    } else {
        println!(
            "Verify rotate '{}': {} passed, {} failed",
            args.name, passed, failed
        );
        std::process::exit(1);
    }
    Ok(())
}

fn verify_dropin(ctx: &CliContext, args: VerifyDropinArgs) -> Result<()> {
    let paths = &ctx.paths;
    let map_name = args
        .service
        .strip_suffix(".service")
        .unwrap_or(&args.service);
    let unit_name = if args.service.ends_with(".service") {
        args.service.clone()
    } else {
        format!("{}.service", args.service)
    };

    let map_file = paths.services.join(format!("{}.conf", map_name));
    if !map_file.is_file() {
        bail!("map file not found: {}", map_file.display());
    }

    let entries = service_map::parse_service_map(&map_file, &paths.credstore)?;
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Check each credential exists
    for entry in &entries {
        let cred_file = if entry.is_custom_path {
            entry.cred_path.clone()
        } else {
            paths
                .credstore
                .join(format!("{}.cred", entry.cred_name))
        };
        if cred_file.is_file() {
            println!("  [PASS] {} exists", entry.cred_name);
            passed += 1;
        } else {
            println!("  [FAIL] {} missing: {}", entry.cred_name, cred_file.display());
            failed += 1;
        }
    }

    // Check drop-in file exists
    let dropin_path = std::path::PathBuf::from(format!(
        "/etc/systemd/system/{}.d/credentials.conf",
        unit_name
    ));
    if dropin_path.is_file() {
        println!("  [PASS] Drop-in installed: {}", dropin_path.display());
        passed += 1;
    } else {
        println!("  [WARN] Drop-in not installed: {}", dropin_path.display());
    }

    println!();
    if failed == 0 {
        println!(
            "Verify dropin '{}': {} passed, 0 failed",
            args.service, passed
        );
    } else {
        println!(
            "Verify dropin '{}': {} passed, {} failed",
            args.service, passed, failed
        );
        std::process::exit(1);
    }
    Ok(())
}

fn verify_all(ctx: &CliContext) -> Result<()> {
    let paths = &ctx.paths;
    let mut total_passed = 0u32;
    let mut total_failed = 0u32;

    // Verify all credentials in vault.toml
    if paths.vault_toml.exists() {
        let vault = metadata::load(&paths.vault_toml)?;
        for cred in &vault.credentials {
            let cred_path = paths
                .credstore
                .join(format!("{}{}", cred.name, constants::CRED_EXTENSION));
            if cred_path.is_file() {
                let tmp = tempfile::NamedTempFile::new()?;
                match systemd::decrypt_to_file(&cred_path, tmp.path()) {
                    Ok(()) => {
                        println!("  [PASS] {}", cred.name);
                        total_passed += 1;
                    }
                    Err(e) => {
                        println!("  [FAIL] {}: {}", cred.name, e);
                        total_failed += 1;
                    }
                }
            } else {
                println!("  [FAIL] {} missing .cred file", cred.name);
                total_failed += 1;
            }
        }
    }

    // Verify service maps
    if paths.services.is_dir() {
        if let Ok(dir) = std::fs::read_dir(&paths.services) {
            for entry in dir.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    if let Some(svc) = path.file_stem().and_then(|s| s.to_str()) {
                        match service_map::parse_service_map(&path, &paths.credstore) {
                            Ok(_) => {
                                println!("  [PASS] Service map '{}' parseable", svc);
                                total_passed += 1;
                            }
                            Err(e) => {
                                println!("  [FAIL] Service map '{}': {}", svc, e);
                                total_failed += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    println!();
    if total_failed == 0 {
        println!("Verify all: {} passed, 0 failed", total_passed);
    } else {
        println!(
            "Verify all: {} passed, {} failed",
            total_passed, total_failed
        );
        std::process::exit(1);
    }
    Ok(())
}
