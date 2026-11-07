//! Command-line interface.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "dllh3x",
    version,
    about = "Read-only DLL search-order / hijacking auditor for Windows PE binaries",
    long_about = "DLLH3x statically audits a PE's import and delay-import tables, models the \
Windows DLL search order, and reports which dependencies could be resolved from a \
writable application directory. It is diagnosis only: it never generates, patches, \
plants, or executes a module."
)]
pub struct Cli {
    /// File or directory to audit.
    pub path: String,

    /// Recurse into subdirectories when PATH is a directory.
    #[arg(short, long)]
    pub recursive: bool,

    /// Emit JSON instead of the terminal report.
    #[arg(short, long)]
    pub json: bool,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Only report findings at or above this risk: info|low|medium|high|critical.
    #[arg(long, value_name = "LEVEL", default_value = "low")]
    pub min_risk: String,

    /// Point the system index at a live System32 directory (e.g. for WSL:
    /// /mnt/c/Windows/System32). Used to resolve 64-bit targets.
    #[arg(long, value_name = "DIR")]
    pub system_root: Option<String>,

    /// Point the index at a live SysWOW64 directory (e.g. for WSL:
    /// /mnt/c/Windows/SysWOW64). Used to resolve 32-bit (x86) targets.
    #[arg(long, value_name = "DIR")]
    pub wow64_root: Option<String>,

    /// Show every reason and remediation line per finding.
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,

    /// Exit non-zero if any finding reaches this risk (for CI gates).
    #[arg(long, value_name = "LEVEL")]
    pub fail_on: Option<String>,
}
