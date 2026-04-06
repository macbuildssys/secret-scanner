use anyhow::Result;
use serde::Serialize;
use crate::detector::Finding;

#[derive(Serialize)]
struct JsonFinding<'a> {
    rule_id: &'a str,
    rule_name: &'a str,
    severity: &'a str,
    path: &'a str,
    line: usize,
}

pub fn render(findings: &[Finding]) -> Result<String> {
    let items: Vec<JsonFinding> = findings
        .iter()
        .map(|f| JsonFinding {
            rule_id: f.rule_id,
            rule_name: f.rule_name,
            severity: f.severity.as_str(),
            path: &f.path,
            line: f.line_number,
        })
        .collect();

    Ok(serde_json::to_string_pretty(&items)?)
}
