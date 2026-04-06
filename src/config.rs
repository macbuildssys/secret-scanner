use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub allowlist: AllowlistConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct ScanConfig {
    pub min_entropy: Option<f64>,
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl AllowlistConfig {
    pub fn matches_pattern(&self, matched_text: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| matched_text.contains(p.as_str()))
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Self> {
        let candidates: Vec<&str> = if let Some(p) = path {
            vec![p]
        } else {
            vec![".secret-scanner.toml"]
        };

        for candidate in candidates {
            let p = Path::new(candidate);
            if p.exists() {
                let contents = std::fs::read_to_string(p)
                    .with_context(|| format!("Failed to read config file: {candidate}"))?;
                let config: Config = toml::from_str(&contents)
                    .with_context(|| format!("Failed to parse config file: {candidate}"))?;
                return Ok(config);
            }
        }

        Ok(Config::default())
    }
}
