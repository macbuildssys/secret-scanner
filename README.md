# secret-scanner

A fast secret and credential scanner written in Rust.

secret-scanner scans source trees for hardcoded secrets, API keys, and credentials. It combines regex pattern matching with Shannon entropy scoring to catch real secrets while suppressing common false positives like placeholder values.

## Features

- 20 built-in rules covering AWS, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, npm, private keys, connection strings, JWTs, and generic patterns

- Shannon entropy scoring filters placeholder values (`changeme`, `your-token-here`) from real secrets

- Respects `.gitignore` automatically

- Parallel scanning via rayon

- Three output formats: terminal (coloured), JSON, SARIF 2.1.0

- SARIF output integrates directly with GitHub Security tab via `upload-sarif`

- Inline suppression with `# secret-scanner:ignore` comments

- Configurable via `.secret-scanner.toml`

- Exit code 1 when findings are present, making it suitable as a CI gate

## Installation

```
cargo install secret-scanner
```

Or build from source:

```
git clone https://github.com/macbuildssys/secret-scanner

cd secret-scanner

cargo build --release

# binary at target/release/secret-scanner
```

## Usage

```
# Scan current directory
secret-scanner

# Scan a specific path
secret-scanner path/to/repo

# Show redacted matched text
secret-scanner . --show-matches

# Output SARIF (for GitHub Security integration)
secret-scanner . --format sarif --output results.sarif

# Output JSON
secret-scanner . --format json

# Scan hidden files too
secret-scanner . --hidden

# Override entropy threshold
secret-scanner . --min-entropy 4.0

# Exclude patterns
secret-scanner . --exclude "*.md,docs/**,tests/**"
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | One or more findings |
| 2 | Scan error (permission denied, invalid config, etc.) |

## Suppressing findings

Add `# secret-scanner:ignore` or `// secret-scanner:ignore` to the end of any line to suppress it:

```
API_KEY=test-key-for-local-dev  # secret-scanner:ignore
```

## Configuration

Create a `.secret-scanner.toml` in the root of your repository:

```
[scan]

min_entropy = 3.5

exclude = ["*.lock", "target/**", "docs/**"]

[allowlist]

paths = ["tests/fixtures/"]

patterns = ["EXAMPLE", "changeme", "your-token-here"]
```

## CI integration

secret-scanner ships with a GitHub Actions workflow. To add it to your repository:

```
- name: Scan for secrets
  run: secret-scanner . --format sarif --output results.sarif || true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear in the repository's Security > Code scanning tab.

## Built-in rules

| ID | Name | Severity |
|----|------|----------|
| SSC001 | AWS access key ID | Critical |
| SSC002 | AWS secret access key | Critical |
| SSC003 | GitHub personal access token | Critical |
| SSC004 | GitHub fine-grained PAT | Critical |
| SSC005 | GitLab personal access token | Critical |
| SSC006 | Private key PEM header | Critical |
| SSC007 | Stripe live secret key | Critical |
| SSC008 | Stripe publishable live key | High |
| SSC009 | Slack token | Critical |
| SSC010 | Slack webhook URL | High |
| SSC011 | JWT token | High |
| SSC012 | PostgreSQL connection string | Critical |
| SSC013 | MySQL connection string | Critical |
| SSC014 | Generic password assignment | High |
| SSC015 | Generic API key assignment | High |
| SSC016 | Generic secret/token assignment | High |
| SSC017 | Twilio account SID | High |
| SSC018 | Twilio auth token | Critical |
| SSC019 | SendGrid API key | Critical |
| SSC020 | npm authentication token | Critical |

## How entropy scoring works

Many credential scanners produce excessive false positives on example config files and documentation. secret-scanner addresses this by computing Shannon entropy on matched strings:

```
H = -sum(p_i * log2(p_i))
```

where `p_i` is the frequency of each character. A string like `changeme` has entropy around 2.8 bits/char. A real AWS secret key sits above 4.5 bits/char. Each rule has a tuned minimum entropy threshold; matched strings that fall below it are discarded.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).

