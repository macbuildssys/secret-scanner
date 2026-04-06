use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secret-scanner")
}

fn dirty_file() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "# test secrets").unwrap();
    writeln!(f, "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456ab").unwrap();
    writeln!(f, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
    writeln!(
        f,
        "DB=postgresql://admin:Sup3rS3cr3tP@ssw0rd!@db.example.com:5432/app"
    )
    .unwrap();
    f
}

fn clean_file() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "# no secrets here").unwrap();
    writeln!(f, "API_KEY=your-token-here").unwrap();
    writeln!(f, "PASSWORD=changeme  # secret-scanner:ignore").unwrap();
    f
}

#[test]
fn clean_file_exits_zero() {
    let tmp = clean_file();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn dirty_file_exits_one() {
    let tmp = dirty_file();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn sarif_output_is_valid_json() {
    let tmp = dirty_file();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--format", "sarif", "--quiet"])
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
    let tmp = dirty_file();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--format", "json", "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output is not valid JSON");
    assert!(parsed.as_array().unwrap().len() > 0);
}

#[test]
fn suppression_comment_skips_line() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456ab  # secret-scanner:ignore"
    )
    .unwrap();
    let output = Command::new(bin())
        .args([tmp.path().to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run secret-scanner");
    assert_eq!(output.status.code(), Some(0));
}
