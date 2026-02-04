use crate::core::paths::VaultPaths;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod credential;
pub mod dropin;
pub mod init;

#[derive(Parser, Debug)]
#[command(name = "goamet-vault", version, about = "Systemd credential wrapper for GoAmet services")]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        let paths = VaultPaths::resolve(self.root)?;
        match self.command {
            Commands::Init(args) => init::run(&paths, args),
            Commands::Create(args) => credential::run_create(&paths, args),
            Commands::Get(args) => credential::run_get(&paths, args),
            Commands::List(args) => credential::run_list(&paths, args),
            Commands::Delete(args) => credential::run_delete(&paths, args),
            Commands::Describe(args) => credential::run_describe(&paths, args),
            Commands::Search(args) => credential::run_search(&paths, args),
            Commands::Rotate(args) => credential::run_rotate(&paths, args),
            Commands::Dropin { command } => dropin::run(&paths, command),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize vault directories and optionally host key
    Init(init::InitArgs),
    /// Create an encrypted credential
    Create(credential::CreateArgs),
    /// Decrypt and output a credential
    Get(credential::GetArgs),
    /// List credentials
    List(credential::ListArgs),
    /// Delete a credential
    Delete(credential::DeleteArgs),
    /// Describe a credential (metadata)
    Describe(credential::DescribeArgs),
    /// Search credentials by name/description/tags
    Search(credential::SearchArgs),
    /// Rotate a credential
    Rotate(credential::RotateArgs),
    /// Generate or apply systemd drop-ins
    Dropin {
        #[command(subcommand)]
        command: dropin::DropinCommand,
    },
}
