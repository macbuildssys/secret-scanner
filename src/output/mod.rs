pub mod json;
pub mod sarif;
pub mod terminal;

use crate::detector::Finding;
use anyhow::Result;

pub fn write_output(
    findings: &[Finding],
    format: &crate::cli::OutputFormat,
    output_path: Option<&str>,
    show_matches: bool,
) -> Result<()> {
    let content = match format {
        crate::cli::OutputFormat::Terminal => {
            terminal::render(findings, show_matches);
            return Ok(());
        }
        crate::cli::OutputFormat::Json => json::render(findings)?,
        crate::cli::OutputFormat::Sarif => sarif::render(findings)?,
    };

    match output_path {
        Some(path) => std::fs::write(path, content)?,
        None => print!("{content}"),
    }

    Ok(())
}
