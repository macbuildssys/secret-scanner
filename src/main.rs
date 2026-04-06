mod cli;
mod config;
mod detector;
mod output;
mod rules;
mod scanner;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    let config = config::Config::load(cli.config.as_deref())?;
    let ruleset = rules::RuleSet::from_builtin()?;

    if !cli.quiet {
        eprintln!(
            "secret-scanner v{} - scanning: {}",
            env!("CARGO_PKG_VERSION"),
            cli.path
        );
    }

    let findings = scanner::run_scan(&cli, &config, &ruleset)?;

    let has_findings = !findings.is_empty();

    output::write_output(
        &findings,
        &cli.format,
        cli.output.as_deref(),
        cli.show_matches,
    )?;

    if has_findings {
        std::process::exit(1);
    }

    Ok(())
}
