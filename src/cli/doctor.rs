//! Diagnostics for vault installation and automation readiness.

use crate::cli::CliContext;
use crate::constants;
use anyhow::Result;
use clap::Args;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Also check for multiple goamet-vault binaries on PATH
    #[arg(long)]
    pub path: bool,
}

pub fn run(ctx: &CliContext, args: DoctorArgs) -> Result<()> {
    let paths = &ctx.paths;
    let mut ok = 0u32;
    let mut warn = 0u32;
    let mut fail = 0u32;

    println!("Doctor: {}", paths);
    if let Some(w) = &ctx.policy_load_warning {
        println!("  [WARN] {}", w);
    }

    // Vault directory existence checks
    if paths.root.is_dir() {
        println!("  [PASS] vault root exists: {}", paths.root.display());
        ok += 1;
    } else {
        println!("  [FAIL] vault root missing: {}", paths.root.display());
        fail += 1;
    }

    if paths.credstore.is_dir() {
        println!("  [PASS] credstore exists: {}", paths.credstore.display());
        ok += 1;
    } else {
        println!("  [WARN] credstore missing: {}", paths.credstore.display());
        warn += 1;
    }

    // systemd-creds existence
    if Command::new("systemd-creds").arg("--version").output().is_ok() {
        println!("  [PASS] systemd-creds available");
        ok += 1;
    } else {
        println!("  [FAIL] systemd-creds not found on PATH");
        fail += 1;
    }

    // Host key presence (best-effort, might require root to inspect perms but exists() is fine)
    let host_key = Path::new(constants::HOST_KEY_PATH);
    if host_key.exists() {
        println!("  [PASS] host key exists: {}", host_key.display());
        ok += 1;
    } else {
        println!("  [WARN] host key missing: {} (run: systemd-creds setup)", host_key.display());
        warn += 1;
    }

    // Permission checks (best-effort; if not accessible, just warn)
    if let Ok(meta) = fs::metadata(&paths.credstore) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode == constants::CREDSTORE_DIR_MODE {
                println!("  [PASS] credstore mode ok: {:04o}", mode);
                ok += 1;
            } else {
                println!(
                    "  [WARN] credstore mode: {:04o} (expected {:04o})",
                    mode,
                    constants::CREDSTORE_DIR_MODE
                );
                warn += 1;
            }
        }
    }

    if args.path {
        let bins = find_bins_on_path("goamet-vault");
        if bins.is_empty() {
            println!("  [WARN] goamet-vault not found on PATH");
            warn += 1;
        } else {
            println!("  [INFO] goamet-vault binaries on PATH:");
            for b in &bins {
                println!("    - {}", b.display());
            }
            if bins.len() > 1 {
                println!("  [WARN] multiple binaries detected; automation should pin /usr/local/bin/goamet-vault");
                warn += 1;
            } else {
                ok += 1;
            }
        }
    }

    // Summary
    println!();
    println!("Doctor summary: {} pass, {} warn, {} fail", ok, warn, fail);
    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn find_bins_on_path(name: &str) -> Vec<PathBuf> {
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    let path = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            out.insert(candidate);
        }
    }
    out.into_iter().collect()
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return (meta.permissions().mode() & 0o111) != 0;
        }
    }
    #[cfg(not(unix))]
    {
        // best-effort on non-unix
        return true;
    }
    false
}
