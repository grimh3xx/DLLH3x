//! DLLH3x — read-only DLL search-order / hijacking auditor.
//!
//! DLLH3x inspects Windows PE binaries on disk and reports where the dynamic
//! loader could resolve a dependency from an attacker-writable application
//! directory. It is strictly a diagnostic: nothing here writes to, patches,
//! plants, or executes a module. Findings come with remediation so the output
//! is actionable for both defenders hardening software and authorized
//! assessors writing up findings.

mod acl;
mod analysis;
mod cli;
mod manifest;
mod pe;
mod report;
mod sysindex;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use owo_colors::OwoColorize;
use walkdir::WalkDir;

use analysis::{analyze, Report, Risk};
use cli::Cli;
use pe::PeInfo;
use sysindex::SystemIndex;

/// Extensions treated as PE candidates during a directory walk.
const PE_EXTS: &[&str] = &["exe", "dll", "ocx", "cpl", "scr", "sys", "drv", "efi"];

fn main() -> ExitCode {
    let args = Cli::parse();

    if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        owo_colors::set_override(false);
    }

    let min_risk = match Risk::from_str(&args.min_risk) {
        Some(r) => r,
        None => {
            eprintln!("invalid --min-risk value: {}", args.min_risk);
            return ExitCode::from(2);
        }
    };
    let fail_on = match args.fail_on.as_deref().map(Risk::from_str) {
        Some(Some(r)) => Some(r),
        Some(None) => {
            eprintln!("invalid --fail-on value: {}", args.fail_on.unwrap());
            return ExitCode::from(2);
        }
        None => None,
    };

    if !args.json {
        print_banner();
    }

    let index = SystemIndex::load(
        args.system_root.as_deref().map(Path::new),
        args.wow64_root.as_deref().map(Path::new),
    );
    if !args.json {
        let sys32 = index.system32();
        let where_from = sys32
            .dir_label()
            .unwrap_or_else(|| "built-in baseline".to_string());
        println!(
            "  {} system index: {} known-dlls, {} System32 modules  ({})",
            "·".dimmed(),
            index.known_count(),
            sys32.len(),
            where_from.dimmed(),
        );
        match index.syswow64() {
            Some(w) => println!(
                "  {} wow64 index:  {} SysWOW64 modules  ({})  — used for x86 targets",
                "·".dimmed(),
                w.len(),
                w.dir_label().unwrap_or_default().dimmed(),
            ),
            None => println!(
                "  {} wow64 index:  {} — x86 targets fall back to the System32 set",
                "·".dimmed(),
                "not loaded".yellow(),
            ),
        }
    }

    let root = PathBuf::from(&args.path);
    if !root.exists() {
        eprintln!("path not found: {}", root.display());
        return ExitCode::from(2);
    }

    let targets = collect_targets(&root, args.recursive);
    if targets.is_empty() {
        eprintln!("no PE files found under {}", root.display());
        return ExitCode::from(2);
    }

    let mut reports: Vec<Report> = Vec::new();
    for target in &targets {
        let pe = match PeInfo::parse(target) {
            Ok(pe) => pe,
            Err(e) => {
                // A single unreadable/non-PE file should not abort a batch.
                if !args.json {
                    eprintln!("  {} skipping {}: {}", "!".yellow(), target.display(), e);
                }
                continue;
            }
        };

        let dir = target.parent().unwrap_or(Path::new("."));
        let app_dir_files = list_dir_lower(dir);
        let exposure = acl::inspect_dir(dir);
        let dotlocal = acl::has_dotlocal(target);
        let manifest = manifest::load(target);

        reports.push(analyze(
            &pe,
            &index,
            dir,
            &app_dir_files,
            &exposure,
            dotlocal,
            manifest.as_ref(),
        ));
    }

    if reports.is_empty() {
        eprintln!("no PE files could be parsed under {}", root.display());
        return ExitCode::from(2);
    }

    // Emit.
    let rendered = if args.json {
        report::to_json(&reports)
    } else {
        String::new()
    };

    if let Some(path) = &args.output {
        let content = if args.json {
            rendered.clone()
        } else {
            report::to_json(&reports)
        };
        if let Err(e) = std::fs::write(path, content) {
            eprintln!("failed to write {path}: {e}");
            return ExitCode::from(2);
        }
        if !args.json {
            println!("  {} report written to {}", "✓".green(), path.bold());
        }
    }

    if args.json {
        if args.output.is_none() {
            println!("{rendered}");
        }
    } else {
        for r in &reports {
            report::print_terminal(r, min_risk, args.verbose);
        }
        print_totals(&reports);
    }

    // CI gate.
    if let Some(threshold) = fail_on {
        let tripped = reports
            .iter()
            .any(|r| r.findings.iter().any(|f| f.risk >= threshold));
        if tripped {
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

/// Gather the set of files to audit.
fn collect_targets(root: &Path, recursive: bool) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let max_depth = if recursive { usize::MAX } else { 1 };
    WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| has_pe_ext(p))
        .collect()
}

fn has_pe_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| PE_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Lowercased file names directly inside `dir`.
fn list_dir_lower(dir: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                set.insert(name.to_ascii_lowercase());
            }
        }
    }
    set
}

fn print_banner() {
    let art = r#"
   ___  _    _    _  _ ____
  |   \| |  | |  | || |__ /__ __
  | |) | |__| |__| __ ||_ \ \ /
  |___/|____|____|_||_|___/_\_\   read-only DLL hijack auditor
"#;
    println!("{}", art.bright_cyan());
}

fn print_totals(reports: &[Report]) {
    if reports.len() < 2 {
        return;
    }
    let mut crit = 0;
    let mut high = 0;
    for r in reports {
        crit += r.counts.critical;
        high += r.counts.high;
    }
    println!(
        "  {} {} binaries audited  ·  {} critical  ·  {} high",
        "Σ".bright_cyan().bold(),
        reports.len(),
        crit.to_string().bright_red(),
        high.to_string().red(),
    );
    println!();
}
