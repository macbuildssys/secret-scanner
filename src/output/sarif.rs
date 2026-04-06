use crate::detector::Finding;
use crate::rules::Severity;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifRuleConfig,
}

#[derive(Serialize)]
struct SarifRuleConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: &'static str,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifact,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifact {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

fn severity_to_sarif_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
    }
}

pub fn render(findings: &[Finding]) -> Result<String> {
    let mut seen_rules: Vec<(&str, &str, &Severity)> = Vec::new();
    for f in findings {
        if !seen_rules.iter().any(|(id, _, _)| *id == f.rule_id) {
            seen_rules.push((f.rule_id, f.rule_name, &f.severity));
        }
    }

    let rules: Vec<SarifRule> = seen_rules
        .iter()
        .map(|(id, name, sev)| SarifRule {
            id,
            name,
            default_configuration: SarifRuleConfig {
                level: severity_to_sarif_level(sev),
            },
        })
        .collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule_id,
            level: severity_to_sarif_level(&f.severity),
            message: SarifMessage {
                text: format!("Possible secret detected by rule: {}", f.rule_name),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifact {
                        uri: f.path.clone(),
                    },
                    region: SarifRegion {
                        start_line: f.line_number,
                    },
                },
            }],
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "secret-scanner",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };

    Ok(serde_json::to_string_pretty(&log)?)
}
