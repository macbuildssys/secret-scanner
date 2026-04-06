pub mod builtin;

use anyhow::{Context, Result};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub pattern: &'static str,
    pub severity: Severity,
    pub min_entropy: Option<f64>,
}

pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Regex,
}

pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn from_builtin() -> Result<Self> {
        let rules = builtin::all_rules()
            .into_iter()
            .map(|r| {
                let regex = Regex::new(r.pattern)
                    .with_context(|| format!("Failed to compile pattern for rule {}", r.id))?;
                Ok(CompiledRule { rule: r, regex })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }
}
