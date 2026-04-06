use crate::detector::Finding;
use crate::rules::Severity;
use owo_colors::OwoColorize;

fn redact(s: &str) -> String {
    let visible = s.chars().take(6).collect::<String>();
    format!("{visible}***")
}

fn severity_label(s: &Severity) -> String {
    match s {
        Severity::Critical => "[CRITICAL]".red().bold().to_string(),
        Severity::High => "[HIGH]".yellow().bold().to_string(),
        Severity::Medium => "[MEDIUM]".cyan().bold().to_string(),
    }
}

pub fn render(findings: &[Finding], show_matches: bool) {
    if findings.is_empty() {
        println!("{}", "No secrets found.".green());
        return;
    }

    for f in findings {
        println!(
            "{} {} {}:{}",
            severity_label(&f.severity),
            f.rule_name.bold().to_string(),
            f.path.blue().to_string(),
            f.line_number.to_string().dimmed()
        );
        println!("   {} {}", "line:".dimmed(), f.line.trim().dimmed());
        if show_matches {
            println!("   {} {}", "match:".dimmed(), redact(&f.matched_text));
        }
    }

    let criticals = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let highs = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let mediums = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();

    println!();
    println!(
        "Found {} finding(s): {} critical, {} high, {} medium",
        findings.len().to_string().bold(),
        criticals.to_string().red(),
        highs.to_string().yellow(),
        mediums.to_string().cyan()
    );
}
