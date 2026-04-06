use crate::rules::{CompiledRule, Severity};

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub path: String,
    pub line_number: usize,
    pub matched_text: String,
    pub line: String,
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn is_suppressed(line: &str) -> bool {
    line.contains("secret-scanner:ignore") || line.contains("nosecret")
}

pub fn scan_line(
    rule: &CompiledRule,
    line: &str,
    line_number: usize,
    path: &str,
    entropy_override: Option<f64>,
) -> Option<Finding> {
    if is_suppressed(line) {
        return None;
    }

    let mat = rule.regex.find(line)?;
    let matched = mat.as_str().to_string();

    let threshold = entropy_override.or(rule.rule.min_entropy);
    if let Some(min_e) = threshold {
        let capture = rule
            .regex
            .captures(line)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| matched.clone());

        if shannon_entropy(&capture) < min_e {
            return None;
        }
    }

    Some(Finding {
        rule_id: rule.rule.id,
        rule_name: rule.rule.name,
        severity: rule.rule.severity.clone(),
        path: path.to_string(),
        line_number,
        matched_text: matched,
        line: line.to_string(),
    })
}
