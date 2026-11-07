//! Human-readable and JSON rendering of an analysis [`Report`].

use owo_colors::OwoColorize;

use crate::analysis::{Report, Risk};
use crate::sysindex::IndexSource;

/// Render a report to the terminal.
pub fn print_terminal(report: &Report, min_risk: Risk, verbose: bool) {
    println!();
    println!("  {} {}", "▸".bright_cyan(), report.target.bold());
    println!(
        "    arch: {}   imphash: {}",
        report.arch.bright_white(),
        report.imphash.as_deref().unwrap_or("-").dimmed()
    );

    let writable = match report.app_dir_writable {
        Some(true) => "writable".bright_red().to_string(),
        Some(false) => "not writable".green().to_string(),
        None => "unknown".yellow().to_string(),
    };
    // Name the directory set actually used: SysWOW64 only when a real WoW64
    // index resolved an x86 target, otherwise the System32 set (x64, or x86
    // falling back to System32 when no SysWOW64 index was loaded).
    let sysdir = if report.wow64_resolution {
        "SysWOW64"
    } else {
        "System32"
    };
    let src = match report.index_source {
        IndexSource::Live => format!(
            "live {} ({})",
            sysdir,
            report.system_dir.as_deref().unwrap_or("?")
        )
        .green()
        .to_string(),
        IndexSource::Baseline => "baseline (no live system dir)".yellow().to_string(),
    };
    let wow = if report.wow64_resolution {
        "  [wow64]".bright_magenta().to_string()
    } else {
        String::new()
    };
    println!("    app dir: {writable}   system index: {src}{wow}");

    if let Some(m) = &report.manifest {
        let origin = match m.source {
            crate::manifest::ManifestSource::Embedded => "embedded",
            crate::manifest::ManifestSource::External => "external",
        };
        println!(
            "    manifest: {} — {} redirected file(s), {} SxS dependenc(ies)",
            origin.bright_magenta(),
            m.redirected_files.len().to_string().bold(),
            m.dependencies.len(),
        );
    }

    let shown: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.risk >= min_risk)
        .collect();

    if shown.is_empty() {
        println!(
            "    {}",
            "no findings at or above the selected risk.".dimmed()
        );
    } else {
        println!();
        for f in shown {
            let tag = colorize_risk(f.risk);
            println!(
                "    {tag}  {}  {}  {}",
                f.dll.bold(),
                format!("[{}]", f.classification.label()).dimmed(),
                format!("({})", f.kind).dimmed(),
            );
            if verbose {
                for r in &f.reasons {
                    println!("        {} {}", "·".dimmed(), r);
                }
                for rem in &f.remediation {
                    println!("        {} {}", "→".bright_green(), rem.green());
                }
            } else if let Some(first) = f.reasons.first() {
                println!("        {} {}", "·".dimmed(), first);
            }
        }
    }

    println!();
    print_summary(report);
    println!();
}

fn print_summary(report: &Report) {
    let c = &report.counts;
    let bar = score_bar(report.surface_score);
    println!(
        "    {} {}  {}",
        "surface score".bold(),
        format!("{:>3}/100", report.surface_score).bold(),
        bar
    );
    println!(
        "    {}  crit {}  high {}  med {}  low {}  info {}",
        "findings:".dimmed(),
        c.critical.to_string().bright_red(),
        c.high.to_string().red(),
        c.medium.to_string().yellow(),
        c.low.to_string().bright_blue(),
        c.info.to_string().dimmed(),
    );
}

fn colorize_risk(risk: Risk) -> String {
    let s = format!("{:<8}", risk.label());
    match risk {
        Risk::Critical => s.on_red().white().bold().to_string(),
        Risk::High => s.bright_red().bold().to_string(),
        Risk::Medium => s.yellow().bold().to_string(),
        Risk::Low => s.bright_blue().to_string(),
        Risk::Info => s.dimmed().to_string(),
    }
}

fn score_bar(score: u32) -> String {
    let width = 24u32;
    let filled = (score * width / 100).min(width);
    let empty = width - filled;
    let bar = format!(
        "{}{}",
        "█".repeat(filled as usize),
        "░".repeat(empty as usize)
    );
    match score {
        85..=100 => bar.bright_red().to_string(),
        55..=84 => bar.red().to_string(),
        25..=54 => bar.yellow().to_string(),
        _ => bar.green().to_string(),
    }
}

/// Serialize a batch of reports to pretty JSON.
pub fn to_json(reports: &[Report]) -> String {
    serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".to_string())
}
