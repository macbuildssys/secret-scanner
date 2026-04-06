use anyhow::Result;
use ignore::{WalkBuilder, WalkState};
use rayon::prelude::*;
use std::fs;
use std::sync::Mutex;

use crate::{
    cli::Cli,
    config::Config,
    detector::{scan_line, Finding},
    rules::RuleSet,
};

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

fn build_exclude_list(cli: &Cli, config: &Config) -> Vec<String> {
    let mut excludes: Vec<String> = Vec::new();
    if let Some(ref ex) = cli.exclude {
        for g in ex.split(',') {
            let g = g.trim().to_string();
            if !g.is_empty() {
                excludes.push(g);
            }
        }
    }
    if let Some(ref ex) = config.scan.exclude {
        excludes.extend(ex.clone());
    }
    excludes
}

pub fn run_scan(cli: &Cli, config: &Config, ruleset: &RuleSet) -> Result<Vec<Finding>> {
    let entropy_override = cli.min_entropy.or(config.scan.min_entropy);
    let excludes = build_exclude_list(cli, config);
    let allowlist_paths: Vec<String> = config.allowlist.paths.clone();

    let entries: Mutex<Vec<ignore::DirEntry>> = Mutex::new(Vec::new());

    let mut builder = WalkBuilder::new(&cli.path);
    builder
        .hidden(!cli.hidden)
        .ignore(!cli.no_ignore)
        .git_ignore(!cli.no_ignore)
        .git_global(!cli.no_ignore);

    builder.build_parallel().run(|| {
        Box::new(|result| {
            let entry = match result {
                Ok(e) => e,
                Err(_) => return WalkState::Continue,
            };

            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }

            let path_str = entry.path().display().to_string();

            if excludes.iter().any(|ex| path_str.contains(ex.as_str())) {
                return WalkState::Skip;
            }

            if allowlist_paths
                .iter()
                .any(|a| path_str.contains(a.as_str()))
            {
                return WalkState::Skip;
            }

            entries.lock().unwrap().push(entry);
            WalkState::Continue
        })
    });

    let entries = entries.into_inner().unwrap();

    let findings: Vec<Finding> = entries
        .par_iter()
        .flat_map(|entry| {
            let path = entry.path();
            let path_str = path.display().to_string();

            let metadata = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => return vec![],
            };

            if metadata.len() > MAX_FILE_SIZE {
                return vec![];
            }

            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(_) => return vec![],
            };

            if is_binary(&bytes) {
                return vec![];
            }

            let content = match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => return vec![],
            };

            let mut local_findings = Vec::new();

            for (line_num, line) in content.lines().enumerate() {
                for compiled in &ruleset.rules {
                    if let Some(finding) =
                        scan_line(compiled, line, line_num + 1, &path_str, entropy_override)
                    {
                        if config.allowlist.matches_pattern(&finding.matched_text) {
                            continue;
                        }
                        local_findings.push(finding);
                    }
                }
            }

            local_findings
        })
        .collect();

    Ok(findings)
}
