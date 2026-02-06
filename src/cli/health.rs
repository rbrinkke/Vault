use crate::cli::CliContext;
use crate::constants;
use crate::core::{credstore, metadata, service_map};
use crate::util::systemd;
use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Args, Debug)]
pub struct HealthArgs {
    /// Try to decrypt each .cred file (slower but thorough)
    #[arg(long)]
    pub decrypt: bool,
}

pub fn run(ctx: &CliContext, args: HealthArgs) -> Result<()> {
    let paths = &ctx.paths;
    let mut passed = 0u32;
    let mut failed = 0u32;

    // 1. Check host key
    let host_key = Path::new(constants::HOST_KEY_PATH);
    if host_key.exists() {
        println!("  [PASS] Host key exists: {}", host_key.display());
        passed += 1;
    } else {
        println!("  [FAIL] Host key missing: {}", host_key.display());
        println!("         Run: systemd-creds setup");
        failed += 1;
    }

    // 1b. TPM2 availability
    let tpm2_available = match systemd::tpm2_status() {
        Ok(status) if status.available => {
            println!("  [PASS] TPM2 available ({})", status.detail());
            passed += 1;
            true
        }
        Ok(_) => {
            println!("  [WARN] TPM2 not available (host-key only encryption)");
            false
        }
        Err(e) => {
            println!("  [WARN] Cannot check TPM2: {}", e);
            false
        }
    };

    // 2. Check credstore permissions
    if paths.credstore.is_dir() {
        let ok = check_mode(&paths.credstore, 0o700);
        if ok {
            println!("  [PASS] Credstore permissions: 0700");
            passed += 1;
        } else {
            let actual = get_mode(&paths.credstore).unwrap_or(0);
            println!("  [FAIL] Credstore permissions: {:04o} (expected 0700)", actual);
            failed += 1;
        }
    } else {
        println!("  [FAIL] Credstore directory missing: {}", paths.credstore.display());
        failed += 1;
    }

    // 3. Check vault.toml permissions
    if paths.vault_toml.exists() {
        let ok = check_mode_one_of(&paths.vault_toml, &[0o600, constants::VAULT_TOML_MODE]);
        if ok {
            println!("  [PASS] vault.toml permissions: 0600/0640");
            passed += 1;
        } else {
            let actual = get_mode(&paths.vault_toml).unwrap_or(0);
            println!(
                "  [FAIL] vault.toml permissions: {:04o} (expected 0600 or {:04o})",
                actual,
                constants::VAULT_TOML_MODE
            );
            failed += 1;
        }
    } else {
        println!("  [WARN] vault.toml not found (not initialized?)");
    }

    // 4. Check .cred files decryptable
    if args.decrypt && paths.credstore.is_dir() {
        let creds = credstore::list_credentials(&paths.credstore)?;
        if creds.is_empty() {
            println!("  [WARN] No .cred files in credstore");
        }
        for entry in &creds {
            let tmp = tempfile::NamedTempFile::new()?;
            match systemd::decrypt_to_file(&entry.path, tmp.path()) {
                Ok(()) => {
                    println!("  [PASS] Decryptable: {}", entry.name);
                    passed += 1;
                }
                Err(e) => {
                    println!("  [FAIL] Cannot decrypt: {} ({})", entry.name, e);
                    failed += 1;
                }
            }
        }
    } else if !args.decrypt && paths.credstore.is_dir() {
        let creds = credstore::list_credentials(&paths.credstore)?;
        println!("  [INFO] {} .cred files found (use --decrypt to verify)", creds.len());
    }

    // 5. Check service map files consistent with vault.toml
    if paths.vault_toml.exists() && paths.services.is_dir() {
        let vault = metadata::load(&paths.vault_toml)?;
        let known_creds: Vec<String> = vault.credentials.iter().map(|c| c.name.clone()).collect();
        let mut map_services: Vec<String> = Vec::new();
        if let Ok(entries) = fs::read_dir(&paths.services) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        map_services.push(name.to_string());
                    }
                }
            }
        }
        for svc in &map_services {
            let map_path = paths.services.join(format!("{}.conf", svc));
            match service_map::parse_service_map(&map_path, &paths.credstore) {
                Ok(entries) => {
                    let warnings = service_map::validate_map(&entries, &known_creds, &paths.credstore);
                    let cred_warnings: Vec<_> = warnings
                        .iter()
                        .filter(|w| w.message.contains("not found in vault.toml"))
                        .collect();
                    if cred_warnings.is_empty() {
                        println!("  [PASS] Service map '{}' consistent with vault.toml", svc);
                        passed += 1;
                    } else {
                        for w in &cred_warnings {
                            println!("  [FAIL] Service map {}: {}", svc, w.message);
                            failed += 1;
                        }
                    }
                    // Report missing .cred files as warnings
                    for w in warnings.iter().filter(|w| w.message.contains(".cred file not found")) {
                        println!("  [WARN] Service map {}: {}", svc, w.message);
                    }
                }
                Err(e) => {
                    println!("  [FAIL] Cannot parse service map '{}': {}", svc, e);
                    failed += 1;
                }
            }
        }
    }

    // 6. Check credential encryption key types
    if tpm2_available && paths.vault_toml.exists() {
        let vault = metadata::load(&paths.vault_toml)?;
        let host_only: Vec<_> = vault
            .credentials
            .iter()
            .filter(|c| c.encryption_key.as_deref() == Some("host"))
            .collect();
        if host_only.is_empty() {
            println!("  [PASS] All credentials use TPM2-backed encryption");
            passed += 1;
        } else {
            println!(
                "  [WARN] {} credential(s) use host-only encryption (TPM2 available): {}",
                host_only.len(),
                host_only.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    // 7. Policy warnings
    if ctx.policy.forbid_host_only_when_tpm2 && !tpm2_available {
        println!("  [WARN] Policy 'forbid_host_only_when_tpm2' set but TPM2 not available");
    }

    // 8. Check audit.log permissions (if exists)
    let audit_path = paths.root.join("audit.log");
    if audit_path.exists() {
        let ok = check_mode_one_of(&audit_path, &[0o600, constants::AUDIT_LOG_MODE]);
        if ok {
            println!("  [PASS] audit.log permissions: 0600/0640");
            passed += 1;
        } else {
            let actual = get_mode(&audit_path).unwrap_or(0);
            println!(
                "  [FAIL] audit.log permissions: {:04o} (expected 0600 or {:04o})",
                actual,
                constants::AUDIT_LOG_MODE
            );
            failed += 1;
        }
    }

    // Summary
    println!();
    if failed == 0 {
        println!("Health check: {} passed, 0 failed", passed);
    } else {
        println!("Health check: {} passed, {} failed", passed, failed);
    }

    Ok(())
}

#[cfg(unix)]
fn check_mode(path: &Path, expected: u32) -> bool {
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777 == expected)
        .unwrap_or(false)
}

#[cfg(unix)]
fn check_mode_one_of(path: &Path, expected: &[u32]) -> bool {
    fs::metadata(path)
        .ok()
        .map(|m| {
            let mode = m.permissions().mode() & 0o777;
            expected.iter().any(|e| *e == mode)
        })
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn check_mode(_path: &Path, _expected: u32) -> bool {
    true
}

#[cfg(unix)]
fn get_mode(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn get_mode(_path: &Path) -> Option<u32> {
    None
}
