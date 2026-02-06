//! CLI routing and command dispatch.

use crate::core::paths::VaultPaths;
use crate::models::policy::PolicySection;
use crate::util::privilege;
use crate::util::journald;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod audit;
pub mod credential;
pub mod dropin;
pub mod health;
pub mod init;
pub mod migrate;
pub mod plan;
pub mod verify;
pub mod doctor;
pub mod test;

/// Shared context passed to all command handlers.
pub struct CliContext {
    pub paths: VaultPaths,
    pub non_interactive: bool,
    pub policy: PolicySection,
    pub policy_load_warning: Option<String>,
}

impl CliContext {
    /// Write an audit log line, and optionally forward it to journald.
    pub fn audit_simple(&self, action: &str, credential: &str) {
        // core audit log errors should be visible to the operator
        if let Err(e) = crate::core::audit_log::log(&self.paths, action, credential) {
            eprintln!("warning: audit log failed: {}", e);
            return;
        }

        if self.policy.journald_audit {
            // Do not include secrets; audit.log already contains metadata only.
            let line = format!(
                "{{\"action\":\"{}\",\"credential\":\"{}\",\"vault\":\"{}\"}}",
                action, credential, self.paths
            );
            journald::forward_line("goamet-vault", &line);
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "goamet-vault", version, about = "Systemd credential wrapper for GoAmet services")]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    pub root: Option<PathBuf>,

    /// Run in non-interactive mode (no prompts, suitable for automation)
    #[arg(long, global = true, env = "GOAMET_VAULT_NON_INTERACTIVE")]
    pub non_interactive: bool,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        let paths = VaultPaths::resolve(self.root)?;

        // Load policy from vault.toml if it exists (best-effort).
        // Non-root users may not be able to read it; that's ok for read-only commands like `doctor`.
        let mut policy_load_warning: Option<String> = None;
        let policy = if paths.vault_toml.exists() {
            match crate::core::metadata::load(&paths.vault_toml) {
                Ok(vault) => vault.policy,
                Err(e) => {
                    policy_load_warning = Some(format!("cannot read policy from vault.toml: {}", e));
                    PolicySection::default()
                }
            }
        } else {
            PolicySection::default()
        };

        let ctx = CliContext {
            paths,
            non_interactive: self.non_interactive,
            policy,
            policy_load_warning,
        };

        // Enforce root for mutating commands
        if self.command.requires_root() {
            privilege::require_root(self.command.name())?;
        }

        match self.command {
            Commands::Init(args) => init::run(&ctx, args),
            Commands::Create(args) => credential::run_create(&ctx, args),
            Commands::Get(args) => credential::run_get(&ctx, args),
            Commands::List(args) => credential::run_list(&ctx, args),
            Commands::Delete(args) => credential::run_delete(&ctx, args),
            Commands::Describe(args) => credential::run_describe(&ctx, args),
            Commands::Search(args) => credential::run_search(&ctx, args),
            Commands::Rotate(args) => credential::run_rotate(&ctx, args),
            Commands::Dropin { command } => dropin::run(&ctx, command),
            Commands::Migrate { command } => migrate::run(&ctx, command),
            Commands::Health(args) => health::run(&ctx, args),
            Commands::Audit { command } => audit::run(&ctx, command),
            Commands::Plan { command } => plan::run(&ctx, command),
            Commands::Verify { command } => verify::run(&ctx, command),
            Commands::Rollback { command } => credential::run_rollback(&ctx, command),
            Commands::Doctor(args) => doctor::run(&ctx, args),
            Commands::Test { command } => test::run(&ctx, command),
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
    /// Migrate secrets from .env files to credstore
    Migrate {
        #[command(subcommand)]
        command: migrate::MigrateCommand,
    },
    /// Run health checks on the vault
    Health(health::HealthArgs),
    /// View the audit trail
    Audit {
        #[command(subcommand)]
        command: audit::AuditCommand,
    },
    /// Dry-run preview of mutating operations
    Plan {
        #[command(subcommand)]
        command: plan::PlanCommand,
    },
    /// Post-operation verification
    Verify {
        #[command(subcommand)]
        command: verify::VerifyCommand,
    },
    /// Rollback a previous operation
    Rollback {
        #[command(subcommand)]
        command: credential::RollbackCommand,
    },
    /// Diagnose installation and configuration (safe, read-only)
    Doctor(doctor::DoctorArgs),
    /// Test transient-unit secret leakage protections (safe: no /etc writes)
    Test {
        #[command(subcommand)]
        command: test::TestCommand,
    },
}

impl Commands {
    /// Whether this command requires root privileges.
    pub fn requires_root(&self) -> bool {
        matches!(
            self,
            Commands::Init(_)
                | Commands::Create(_)
                | Commands::Delete(_)
                | Commands::Rotate(_)
                | Commands::Dropin {
                    command: dropin::DropinCommand::Apply(_)
                }
                | Commands::Migrate {
                    command: migrate::MigrateCommand::Import(_)
                }
                | Commands::Rollback { .. }
                | Commands::Test { .. }
        )
    }

    /// Command name for error messages.
    pub fn name(&self) -> &str {
        match self {
            Commands::Init(_) => "init",
            Commands::Create(_) => "create",
            Commands::Get(_) => "get",
            Commands::List(_) => "list",
            Commands::Delete(_) => "delete",
            Commands::Describe(_) => "describe",
            Commands::Search(_) => "search",
            Commands::Rotate(_) => "rotate",
            Commands::Dropin { .. } => "dropin",
            Commands::Migrate { .. } => "migrate",
            Commands::Health(_) => "health",
            Commands::Audit { .. } => "audit",
            Commands::Plan { .. } => "plan",
            Commands::Verify { .. } => "verify",
            Commands::Rollback { .. } => "rollback",
            Commands::Doctor(_) => "doctor",
            Commands::Test { .. } => "test",
        }
    }
}
