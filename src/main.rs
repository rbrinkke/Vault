use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = goamet_vault::cli::Cli::parse();
    cli.run()
}
