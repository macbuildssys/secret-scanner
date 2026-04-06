use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "secret-scanner",
    version,
    about = "A fast secret and credential scanner",
    long_about = "secret-scanner scans files and directories for hardcoded secrets, credentials, and API keys.\n\
                  It uses regex patterns combined with Shannon entropy scoring to reduce false positives."
)]
pub struct Cli {
    /// Path to scan (file or directory). Defaults to current directory.
    #[arg(default_value = ".")]
    pub path: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Write output to a file instead of stdout
    #[arg(short, long)]
    pub output: Option<String>,

    /// Also scan files ignored by .gitignore
    #[arg(long)]
    pub no_ignore: bool,

    /// Also scan hidden files and directories
    #[arg(long)]
    pub hidden: bool,

    /// Suppress all output except findings (exit code: 0=clean, 1=found)
    #[arg(short, long)]
    pub quiet: bool,

    /// Show redacted matched text in terminal output
    #[arg(long)]
    pub show_matches: bool,

    /// Minimum entropy threshold override (default per-rule)
    #[arg(long)]
    pub min_entropy: Option<f64>,

    /// Comma-separated patterns to exclude (matched against file paths)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Path to a config file (default: .secret-scanner.toml in current directory)
    #[arg(long)]
    pub config: Option<String>,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}
