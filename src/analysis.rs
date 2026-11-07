//! Hijackability analysis.
//!
//! For each imported module DLLH3x decides, using the Windows DLL search order
//! and the system index, whether the module could be resolved from the
//! application directory by an attacker who can write there. It never produces
//! or plants anything — every result is a diagnosis plus remediation.

use std::collections::HashSet;

use serde::Serialize;

use crate::manifest::Manifest;
use crate::pe::{ImportKind, PeInfo};
use crate::sysindex::{IndexSource, SystemIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Info => "INFO",
            Risk::Low => "LOW",
            Risk::Medium => "MEDIUM",
            Risk::High => "HIGH",
            Risk::Critical => "CRITICAL",
        }
    }
    pub fn from_str(s: &str) -> Option<Risk> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Risk::Info),
            "low" => Some(Risk::Low),
            "medium" => Some(Risk::Medium),
            "high" => Some(Risk::High),
            "critical" => Some(Risk::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// KnownDLL — always from System32, not hijackable on disk.
    KnownDll,
    /// API-set contract — resolved by schema, not hijackable on disk.
    ApiSet,
    /// Present in System32 and loaded from there under SafeDllSearchMode.
    SystemDll,
    /// A private module shipped next to the binary (legitimate app-local).
    AppLocalDll,
    /// App-local module whose name shadows a System32 module (redirection).
    ShadowingDll,
    /// Redirected to the application directory by a SxS / activation-context
    /// manifest `<file>` entry — an intended private assembly.
    ManifestRedirected,
    /// Not found in System32 and absent from the app dir: an empty slot an
    /// attacker can fill — the classic phantom / search-order hijack.
    PhantomDll,
}

impl Classification {
    pub fn label(self) -> &'static str {
        match self {
            Classification::KnownDll => "known-dll",
            Classification::ApiSet => "api-set",
            Classification::SystemDll => "system-dll",
            Classification::AppLocalDll => "app-local",
            Classification::ShadowingDll => "shadowing",
            Classification::ManifestRedirected => "manifest-redirected",
            Classification::PhantomDll => "phantom",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub dll: String,
    #[serde(rename = "import_kind")]
    pub kind: &'static str,
    pub classification: Classification,
    pub risk: Risk,
    pub score: u32,
    pub reasons: Vec<String>,
    pub remediation: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub arch: String,
    pub is_64: bool,
    pub imphash: Option<String>,
    /// Whether the directory holding the binary is writable by this process —
    /// a proxy for "an attacker could plant a DLL here".
    pub app_dir_writable: Option<bool>,
    pub index_source: IndexSource,
    /// The live system directory used to resolve this binary's imports
    /// (System32 for x64, SysWOW64 for x86), or null when the baseline was used.
    pub system_dir: Option<String>,
    /// True when a 32-bit target was resolved against a real SysWOW64 index.
    pub wow64_resolution: bool,
    /// Summary of the SxS / activation-context manifest, if one was found.
    pub manifest: Option<ManifestSummary>,
    pub surface_score: u32,
    pub counts: Counts,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestSummary {
    pub source: crate::manifest::ManifestSource,
    pub redirected_files: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Analyze a parsed PE against the system index.
///
/// `app_dir_files` is the set of lowercased file names sitting next to the
/// binary; `writable` reports whether that directory is writable.
pub fn analyze(
    pe: &PeInfo,
    index: &SystemIndex,
    app_dir_files: &HashSet<String>,
    writable: Option<bool>,
    manifest: Option<&Manifest>,
) -> Report {
    let mut findings = Vec::new();

    // Pick the system directory the loader would actually use for this target:
    // SysWOW64 for a 32-bit image, System32 for a 64-bit one.
    let arch_index = index.arch_index(pe.is_64);
    let wow64_resolution = !pe.is_64 && index.syswow64().is_some();

    for dll in &pe.imports {
        let name = &dll.name;
        let lower = name.to_ascii_lowercase();
        let present_locally = app_dir_files.contains(&lower);
        let in_system = arch_index.contains(name);

        let (classification, mut risk, mut reasons) = if index.is_api_set(name) {
            (
                Classification::ApiSet,
                Risk::Info,
                vec![
                    "Resolved by the API-set schema; not loadable from the application directory."
                        .to_string(),
                ],
            )
        } else if index.is_known_dll(name) {
            (
                    Classification::KnownDll,
                    Risk::Info,
                    vec!["Listed in KnownDLLs; always mapped from System32 regardless of the app directory.".to_string()],
                )
        } else if manifest.map(|m| m.redirects(name)).unwrap_or(false) {
            // A SxS manifest <file> entry pins this module to the application
            // directory via the activation context, ahead of the search order.
            if present_locally {
                (
                    Classification::ManifestRedirected,
                    Risk::Low,
                    vec![format!(
                        "{name} is redirected to the application directory by the SxS manifest — an intended private assembly."
                    )],
                )
            } else {
                (
                    Classification::ManifestRedirected,
                    Risk::High,
                    vec![format!(
                        "{name} is declared as a manifest <file> redirect but is absent from the application directory — the declared private assembly is missing, so the slot can be filled."
                    )],
                )
            }
        } else if present_locally && in_system {
            (
                    Classification::ShadowingDll,
                    Risk::High,
                    vec![format!(
                        "A module named {name} ships next to the binary but also exists in System32; the local copy shadows the system one."
                    )],
                )
        } else if present_locally {
            (
                Classification::AppLocalDll,
                Risk::Low,
                vec!["Private module present in the application directory.".to_string()],
            )
        } else if in_system {
            (
                Classification::SystemDll,
                Risk::Info,
                vec![format!(
                    "Present in {sysdir}; loaded from there under SafeDllSearchMode.",
                    sysdir = if pe.is_64 {
                        "System32"
                    } else {
                        "the system directory (SysWOW64)"
                    }
                )],
            )
        } else {
            (
                    Classification::PhantomDll,
                    Risk::High,
                    vec![format!(
                        "{name} is not in the system directory ({sysdir}) and is absent from the application directory — the application directory is searched first, leaving an empty slot.",
                        sysdir = if pe.is_64 { "System32" } else { "SysWOW64" }
                    )],
                )
        };

        // The application directory is first in the search order for the EXE's
        // own imports, so writability turns candidates into live exposure.
        match (classification, writable) {
            (Classification::PhantomDll, Some(true)) => {
                risk = Risk::Critical;
                reasons.push(
                    "The application directory is writable, so the empty slot can be filled by a non-privileged user."
                        .to_string(),
                );
            }
            (Classification::PhantomDll, Some(false)) => {
                reasons.push(
                    "The application directory is not writable by this process; confirm ACLs on the real deployment path."
                        .to_string(),
                );
            }
            (Classification::ShadowingDll, Some(true)) => {
                risk = Risk::Critical;
                reasons.push(
                    "The application directory is writable, so the shadowing copy can be replaced."
                        .to_string(),
                );
            }
            (Classification::SystemDll, Some(true)) => {
                risk = Risk::Low;
                reasons.push(
                    "If SafeDllSearchMode is disabled or the import is loaded by relative path, a writable app directory can still win the search."
                        .to_string(),
                );
            }
            (Classification::ManifestRedirected, Some(true)) => {
                // Still redirected, but a writable dir means the pinned
                // private assembly can be swapped out.
                if risk < Risk::Medium {
                    risk = Risk::Medium;
                }
                reasons.push(
                    "The application directory is writable, so even the manifest-pinned assembly can be replaced."
                        .to_string(),
                );
            }
            _ => {}
        }

        if dll.kind == ImportKind::Delay && risk >= Risk::Low {
            reasons.push(
                "Delay-loaded: resolution happens at first use, a timing often missed by load-time integrity checks."
                    .to_string(),
            );
        }

        let remediation = remediation_for(classification, name);
        let score = base_score(risk);

        findings.push(Finding {
            dll: name.clone(),
            kind: dll.kind.label(),
            classification,
            risk,
            score,
            reasons,
            remediation,
        });
    }

    // Order findings by risk (desc), then name, for a stable report.
    findings.sort_by(|a, b| {
        b.risk
            .cmp(&a.risk)
            .then_with(|| a.dll.to_ascii_lowercase().cmp(&b.dll.to_ascii_lowercase()))
    });

    let mut counts = Counts::default();
    for f in &findings {
        match f.risk {
            Risk::Critical => counts.critical += 1,
            Risk::High => counts.high += 1,
            Risk::Medium => counts.medium += 1,
            Risk::Low => counts.low += 1,
            Risk::Info => counts.info += 1,
        }
    }
    counts.total = findings.len();

    let manifest_summary = manifest.map(|m| {
        let mut files: Vec<String> = m.files.iter().cloned().collect();
        files.sort();
        ManifestSummary {
            source: m.source,
            redirected_files: files,
            dependencies: m.dependencies.clone(),
        }
    });

    Report {
        target: pe.path.display().to_string(),
        arch: pe.machine.clone(),
        is_64: pe.is_64,
        imphash: pe.imphash.clone(),
        app_dir_writable: writable,
        index_source: arch_index.source,
        system_dir: arch_index.dir_label(),
        wow64_resolution,
        manifest: manifest_summary,
        surface_score: surface_score(&counts),
        counts,
        findings,
    }
}

fn base_score(risk: Risk) -> u32 {
    match risk {
        Risk::Critical => 95,
        Risk::High => 75,
        Risk::Medium => 50,
        Risk::Low => 20,
        Risk::Info => 0,
    }
}

/// Aggregate exposure for the whole binary, 0–100. Weighted so that a single
/// critical dominates, while a long tail of low findings cannot inflate it.
fn surface_score(counts: &Counts) -> u32 {
    let raw = counts.critical as u32 * 100
        + counts.high as u32 * 45
        + counts.medium as u32 * 18
        + counts.low as u32 * 4;
    if counts.critical > 0 {
        raw.clamp(85, 100)
    } else if counts.high > 0 {
        raw.clamp(55, 90)
    } else {
        raw.min(50)
    }
}

fn remediation_for(c: Classification, name: &str) -> Vec<String> {
    match c {
        Classification::KnownDll | Classification::ApiSet => Vec::new(),
        Classification::SystemDll => vec![
            format!("Load {name} via its full System32 path, or call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) at startup."),
            "Keep SafeDllSearchMode enabled (it is by default on supported Windows).".to_string(),
        ],
        Classification::AppLocalDll => vec![
            "Restrict ACLs on the install directory so standard users cannot write to it.".to_string(),
            "Consider signing and verifying the module, or embedding a load-time integrity check.".to_string(),
        ],
        Classification::ShadowingDll => vec![
            format!("Rename or remove the app-local {name} so it cannot shadow the System32 module, or load the system copy by full path."),
            "Enable a packaged/app-local redirection manifest only for modules you intend to redirect.".to_string(),
        ],
        Classification::ManifestRedirected => vec![
            "Restrict write access to the install directory so the manifest-pinned assembly cannot be swapped.".to_string(),
            format!("Sign and verify {name}, and ship the declared <file> so the redirect never falls back to the search order."),
        ],
        Classification::PhantomDll => vec![
            format!("Do not import {name} by bare name; resolve it with an explicit, validated path."),
            "Call SetDefaultDllDirectories to remove the application directory from the search path, and add LOAD_LIBRARY_SEARCH_* flags per LoadLibraryEx call.".to_string(),
            "Lock down write access to the install directory.".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_orders_correctly() {
        assert!(Risk::Critical > Risk::High);
        assert!(Risk::High > Risk::Medium);
        assert!(Risk::Low > Risk::Info);
        assert_eq!(Risk::from_str("CRITICAL"), Some(Risk::Critical));
        assert_eq!(Risk::from_str("nope"), None);
    }

    #[test]
    fn surface_score_is_dominated_by_criticals() {
        let crit = Counts {
            critical: 1,
            high: 0,
            medium: 0,
            low: 40,
            info: 10,
            total: 51,
        };
        assert!(surface_score(&crit) >= 85);

        let clean = Counts {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 30,
            total: 30,
        };
        assert_eq!(surface_score(&clean), 0);

        let highs = Counts {
            critical: 0,
            high: 2,
            medium: 0,
            low: 0,
            info: 0,
            total: 2,
        };
        let s = surface_score(&highs);
        assert!((55..=90).contains(&s));
    }
}
