use crate::cli::CliContext;
use crate::core::audit_log;
use anyhow::Result;
use chrono::{DateTime, Local};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Table};

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Display the audit trail
    Log(AuditLogArgs),
    /// Verify audit chain integrity
    Verify(AuditVerifyArgs),
}

#[derive(Args, Debug)]
pub struct AuditLogArgs {
    /// Maximum number of entries to display
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct AuditVerifyArgs {}

pub fn run(ctx: &CliContext, cmd: AuditCommand) -> Result<()> {
    match cmd {
        AuditCommand::Log(args) => run_log(ctx, args),
        AuditCommand::Verify(_) => run_verify(ctx),
    }
}

fn run_log(ctx: &CliContext, args: AuditLogArgs) -> Result<()> {
    let entries = audit_log::read_log(&ctx.paths, Some(args.limit))?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Timestamp").add_attribute(Attribute::Bold),
        Cell::new("Action").add_attribute(Attribute::Bold),
        Cell::new("Credential").add_attribute(Attribute::Bold),
        Cell::new("Actor").add_attribute(Attribute::Bold),
        Cell::new("Result").add_attribute(Attribute::Bold),
    ]);

    for entry in &entries {
        let local: DateTime<Local> = entry.timestamp.into();
        let result_str = match &entry.result {
            Some(r) if r.success => "OK".to_string(),
            Some(r) => format!("FAIL: {}", r.error.as_deref().unwrap_or("?")),
            None => "-".to_string(),
        };
        table.add_row(vec![
            local.format("%Y-%m-%d %H:%M:%S").to_string(),
            entry.action.clone(),
            entry.credential.clone(),
            entry.actor.clone(),
            result_str,
        ]);
    }

    println!("{}", table);
    println!("\n{} entries shown.", entries.len());
    Ok(())
}

fn run_verify(ctx: &CliContext) -> Result<()> {
    let (total, errors) = audit_log::verify_chain(&ctx.paths)?;

    if total == 0 {
        println!("No audit entries to verify.");
        return Ok(());
    }

    for err in &errors {
        println!("  [FAIL] {}", err);
    }

    println!();
    if errors.is_empty() {
        println!("Audit chain: {} entries verified, 0 errors", total);
    } else {
        println!(
            "Audit chain: {} entries, {} errors",
            total,
            errors.len()
        );
        std::process::exit(1);
    }
    Ok(())
}
