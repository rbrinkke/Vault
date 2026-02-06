use crate::cli::CliContext;
use crate::constants;
use crate::core::dropin_gen::generate_dropin;
use crate::core::file_lock::FileLock;
use crate::core::paths::VaultPaths;
use crate::util::fs as vault_fs;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Subcommand, Debug)]
pub enum DropinCommand {
    /// Generate a systemd drop-in for credentials
    Generate(DropinGenerateArgs),
    /// Generate and install the drop-in to /etc/systemd/system
    Apply(DropinApplyArgs),
    /// Show diff between generated and installed drop-in
    Diff(DropinDiffArgs),
}

#[derive(Args, Debug)]
pub struct DropinGenerateArgs {
    pub service: String,

    /// Map file to read (default: `services/<service>.conf`)
    #[arg(long, value_name = "PATH")]
    pub map_file: Option<PathBuf>,

    /// Directory for .cred files (default: credstore)
    #[arg(long, value_name = "PATH")]
    pub cred_dir: Option<PathBuf>,

    /// Output directory for drop-in (default: `units/<service>.service.d`)
    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    /// Do not emit Environment= lines
    #[arg(long)]
    pub no_env: bool,

    /// Disable hardening flags in the drop-in
    #[arg(long)]
    pub no_hardening: bool,

    /// Also install the drop-in to /etc/systemd/system and reload
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args, Debug)]
pub struct DropinApplyArgs {
    pub service: String,

    #[arg(long, value_name = "PATH")]
    pub map_file: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub cred_dir: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    #[arg(long)]
    pub no_env: bool,

    /// Disable hardening flags in the drop-in
    #[arg(long)]
    pub no_hardening: bool,

    /// Required confirmation because this writes to /etc/systemd/system and reloads systemd
    #[arg(long)]
    pub confirm: bool,
}

#[derive(Args, Debug)]
pub struct DropinDiffArgs {
    pub service: String,

    #[arg(long, value_name = "PATH")]
    pub map_file: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub cred_dir: Option<PathBuf>,

    /// Do not emit Environment= lines
    #[arg(long)]
    pub no_env: bool,

    /// Disable hardening flags in the drop-in
    #[arg(long)]
    pub no_hardening: bool,
}

pub fn run(ctx: &CliContext, cmd: DropinCommand) -> Result<()> {
    let paths = &ctx.paths;
    match cmd {
        DropinCommand::Generate(args) => {
            let apply = args.apply;
            run_generate(paths, args, apply, false)
        }
        DropinCommand::Apply(args) => {
            if !ctx.policy.is_service_allowed(&args.service) {
                bail!(
                    "policy: service '{}' not allowed (service_allowlist enforced)",
                    args.service
                );
            }
            if !args.confirm {
                bail!("refusing to write to /etc/systemd/system without --confirm");
            }
            let gen = DropinGenerateArgs {
                service: args.service,
                map_file: args.map_file,
                cred_dir: args.cred_dir,
                out_dir: args.out_dir,
                no_env: args.no_env,
                no_hardening: args.no_hardening,
                apply: true,
            };
            run_generate(paths, gen, true, true)
        }
        DropinCommand::Diff(args) => run_diff(paths, args),
    }
}

fn run_generate(paths: &VaultPaths, args: DropinGenerateArgs, apply: bool, use_lock: bool) -> Result<()> {
    let _vault_lock = if use_lock {
        Some(FileLock::exclusive(&paths.vault_lock)?)
    } else {
        None
    };
    let (unit_name, map_name) = normalize_service_name(&args.service);

    let map_file = resolve_path(
        &paths.root,
        args.map_file
            .unwrap_or_else(|| paths.services.join(format!("{}.conf", map_name))),
    );
    let cred_dir = resolve_path(
        &paths.root,
        args.cred_dir.unwrap_or_else(|| paths.credstore.clone()),
    );
    let out_dir = resolve_path(
        &paths.root,
        args.out_dir
            .unwrap_or_else(|| paths.units.join(format!("{}.d", unit_name))),
    );

    if !map_file.is_file() {
        bail!("map file not found: {}", map_file.display());
    }

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("create output dir {}", out_dir.display()))?;
    let out_file = out_dir.join("credentials.conf");

    let dropin = generate_dropin(&map_file, &cred_dir, args.no_env, !args.no_hardening)?;
    fs::write(&out_file, dropin).with_context(|| format!("write {}", out_file.display()))?;
    println!("Wrote {}", out_file.display());

    if apply {
        apply_dropin(&unit_name, &out_file)?;
    }

    Ok(())
}

fn run_diff(paths: &VaultPaths, args: DropinDiffArgs) -> Result<()> {
    let (unit_name, map_name) = normalize_service_name(&args.service);

    let map_file = resolve_path(
        &paths.root,
        args.map_file
            .unwrap_or_else(|| paths.services.join(format!("{}.conf", map_name))),
    );
    let cred_dir = resolve_path(
        &paths.root,
        args.cred_dir.unwrap_or_else(|| paths.credstore.clone()),
    );

    if !map_file.is_file() {
        bail!("map file not found: {}", map_file.display());
    }

    let generated = generate_dropin(&map_file, &cred_dir, args.no_env, !args.no_hardening)?;
    let target_file = PathBuf::from(format!(
        "/etc/systemd/system/{}.d/credentials.conf",
        unit_name
    ));

    if !target_file.is_file() {
        println!(
            "No installed drop-in at {}. Generated output:\n{}",
            target_file.display(),
            generated
        );
        return Ok(());
    }

    let current = fs::read_to_string(&target_file)
        .with_context(|| format!("read {}", target_file.display()))?;

    if current == generated {
        println!("No diff: generated output matches {}", target_file.display());
        return Ok(());
    }

    print_diff(&current, &generated);
    Ok(())
}

fn print_diff(current: &str, generated: &str) {
    println!("--- current");
    println!("+++ generated");
    for line in current.lines() {
        println!("-{}", line);
    }
    for line in generated.lines() {
        println!("+{}", line);
    }
}

fn apply_dropin(unit_name: &str, source: &Path) -> Result<()> {
    let target_dir = PathBuf::from(format!("/etc/systemd/system/{}.d", unit_name));
    let target_file = target_dir.join("credentials.conf");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("create {}", target_dir.display()))?;
    fs::copy(source, &target_file)
        .with_context(|| format!("copy to {}", target_file.display()))?;
    vault_fs::set_permissions(&target_file, constants::CRED_FILE_MODE)?;

    if systemctl_available() {
        let status = Command::new("systemctl").arg("daemon-reload").status();
        if let Ok(status) = status {
            if !status.success() {
                eprintln!("warning: systemctl daemon-reload failed");
            }
        }
    }

    println!("Installed {}", target_file.display());
    Ok(())
}

fn resolve_path(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn normalize_service_name(service: &str) -> (String, String) {
    if let Some(stripped) = service.strip_suffix(".service") {
        (service.to_string(), stripped.to_string())
    } else {
        (format!("{}.service", service), service.to_string())
    }
}

fn systemctl_available() -> bool {
    Command::new("systemctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
