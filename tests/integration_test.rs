use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secret-scanner")
}

#[test]
fn clean_file_exits_zero() {
    let output = Command::new(bin())
        .args(["tests/fixtures/clean.env", "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0 on clean file, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dirty_file_exits_one() {
    let output = Command::new(bin())
        .args(["tests/fixtures/dirty.env", "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 on dirty file"
    );
}

#[test]
fn sarif_output_is_valid_json() {
    let output = Command::new(bin())
        .args(["tests/fixtures/dirty.env", "--format", "sarif", "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("SARIF output is not valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"][0]["results"].as_array().unwrap().len() > 0);
}

#[test]
fn json_output_is_valid_array() {
    let output = Command::new(bin())
        .args(["tests/fixtures/dirty.env", "--format", "json", "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output is not valid JSON");
    assert!(parsed.as_array().is_some(), "expected a JSON array");
    assert!(parsed.as_array().unwrap().len() > 0);
}

#[test]
fn suppression_comment_skips_line() {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456ab  # secret-scanner:ignore"
    )
    .unwrap();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(
        output.status.code(),
        Some(0),
        "suppressed line should produce no findings"
    );
}
