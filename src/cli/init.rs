use crate::cli::CliContext;
use crate::constants;
use crate::core::metadata;
use crate::util::{fs as vault_fs, systemd};
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Run systemd-creds setup to ensure host key exists
    #[arg(long)]
    pub setup: bool,
}

pub fn run(ctx: &CliContext, args: InitArgs) -> Result<()> {
    let paths = &ctx.paths;
    vault_fs::ensure_dir(&paths.credstore, constants::CREDSTORE_DIR_MODE)?;
    vault_fs::ensure_dir(&paths.services, constants::SERVICES_DIR_MODE)?;
    vault_fs::ensure_dir(&paths.units, constants::UNITS_DIR_MODE)?;

    let mut vault = metadata::load(&paths.vault_toml)?;
    metadata::ensure_vault_section(&mut vault, Some(paths.credstore.display().to_string()));
    metadata::save(&paths.vault_toml, &vault)?;

    if args.setup {
        systemd::setup()?;
    }

    println!("vault initialized at {}", paths.root.display());

    match systemd::has_tpm2() {
        Ok(true) => println!("TPM2: available (new credentials will use host+tpm2)"),
        Ok(false) => println!("TPM2: not available (using host-key only)"),
        Err(_) => {}
    }

    Ok(())
}
