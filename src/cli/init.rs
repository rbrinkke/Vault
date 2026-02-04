use crate::core::metadata;
use crate::core::paths::VaultPaths;
use crate::util::{fs as vault_fs, systemd};
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Run systemd-creds setup to ensure host key exists
    #[arg(long)]
    pub setup: bool,
}

pub fn run(paths: &VaultPaths, args: InitArgs) -> Result<()> {
    vault_fs::ensure_dir(&paths.credstore, 0o700)?;
    vault_fs::ensure_dir(&paths.services, 0o755)?;
    vault_fs::ensure_dir(&paths.units, 0o755)?;

    let mut vault = metadata::load(&paths.vault_toml)?;
    metadata::ensure_vault_section(&mut vault, Some(paths.credstore.display().to_string()));
    metadata::save(&paths.vault_toml, &vault)?;

    if args.setup {
        systemd::setup()?;
    }

    println!("vault initialized at {}", paths.root.display());
    Ok(())
}
