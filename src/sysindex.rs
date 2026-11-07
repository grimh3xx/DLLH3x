//! System module index.
//!
//! DLLH3x needs to know, for any imported module name, whether Windows would
//! resolve it from a protected/system location (and therefore NOT from the
//! application directory). Three buckets matter:
//!
//!   * **KnownDLLs**  — mapped from the `\KnownDlls` object directory; always
//!     loaded from System32, immune to search-order hijacking.
//!   * **API sets**   — `api-ms-win-*` / `ext-ms-*`; resolved by the API-set
//!     schema, never from disk next to the binary.
//!   * **System32**   — present under System32/SysWOW64; under SafeDllSearchMode
//!     these resolve from the system directory, not the app directory.
//!
//! A module that is NONE of the above is an application-supplied dependency and
//! is a search-order hijack candidate.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Embedded fallbacks, used only when no live System32 is available.
const KNOWN_DLLS_TXT: &str = include_str!("../data/knowndlls.txt");
const SYSTEM32_BASELINE_TXT: &str = include_str!("../data/system32_baseline.txt");

/// How the system-module set was sourced. Reported so a reader never mistakes
/// a baseline guess for ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexSource {
    /// Read from a real System32 directory (Windows, or via `--system-root`).
    Live,
    /// Built-in baseline list (running off-Windows, no system root given).
    Baseline,
}

pub struct SystemIndex {
    known_dlls: HashSet<String>,  // lowercase, no extension
    system_dlls: HashSet<String>, // lowercase, with .dll/.drv extension
    pub source: IndexSource,
    pub system_root: Option<PathBuf>,
}

impl SystemIndex {
    /// Build the index. If `system_root` is given it is read live; otherwise on
    /// Windows the real System32 is read, and failing that the baseline is used.
    pub fn load(system_root: Option<&Path>) -> Self {
        let known_dlls = parse_lines(KNOWN_DLLS_TXT);

        if let Some(root) = system_root {
            if let Some(dlls) = read_live_system32(root) {
                return SystemIndex {
                    known_dlls,
                    system_dlls: dlls,
                    source: IndexSource::Live,
                    system_root: Some(root.to_path_buf()),
                };
            }
        }

        #[cfg(windows)]
        {
            let root = default_system32();
            if let Some(dlls) = read_live_system32(&root) {
                return SystemIndex {
                    known_dlls,
                    system_dlls: dlls,
                    source: IndexSource::Live,
                    system_root: Some(root),
                };
            }
        }

        SystemIndex {
            known_dlls,
            system_dlls: parse_lines(SYSTEM32_BASELINE_TXT),
            source: IndexSource::Baseline,
            system_root: None,
        }
    }

    /// True for KnownDLLs (and their forwarded dependencies).
    pub fn is_known_dll(&self, name: &str) -> bool {
        self.known_dlls.contains(&strip_ext(name))
    }

    /// True for API-set contract names, which are never hijackable on disk.
    pub fn is_api_set(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n.starts_with("api-ms-win") || n.starts_with("ext-ms-")
    }

    /// True if the module exists in the resolved System32 set.
    pub fn in_system32(&self, name: &str) -> bool {
        self.system_dlls.contains(&name.to_ascii_lowercase())
    }

    pub fn known_count(&self) -> usize {
        self.known_dlls.len()
    }
    pub fn system_count(&self) -> usize {
        self.system_dlls.len()
    }
}

fn parse_lines(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// Index every file name directly under a System32-like directory.
///
/// The loader resolves an import by its exact file name, and modules are
/// imported under several extensions (`.dll`, `.drv`, `.cpl`, `.ocx`, ...), so
/// we index all names rather than filter by extension and risk false phantoms.
fn read_live_system32(root: &Path) -> Option<HashSet<String>> {
    let entries = fs::read_dir(root).ok()?;
    let mut set = HashSet::new();
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            if let Some(name) = entry.file_name().to_str() {
                set.insert(name.to_ascii_lowercase());
            }
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

#[cfg(windows)]
fn default_system32() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    Path::new(&root).join("System32")
}

/// Lowercase a module name and drop a trailing `.dll`/`.drv`/`.ocx`/`.sys`.
fn strip_ext(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for ext in [".dll", ".drv", ".ocx", ".sys"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    lower
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_extension_case_insensitively() {
        assert_eq!(strip_ext("KERNEL32.DLL"), "kernel32");
        assert_eq!(strip_ext("bthprops.cpl"), "bthprops.cpl"); // .cpl is kept
        assert_eq!(strip_ext("ntoskrnl.sys"), "ntoskrnl");
    }

    #[test]
    fn classifies_known_and_apiset() {
        let idx = SystemIndex::load(None);
        assert!(idx.is_known_dll("KERNEL32.dll"));
        assert!(idx.is_known_dll("ntdll"));
        assert!(idx.is_api_set("api-ms-win-core-synch-l1-2-0.dll"));
        assert!(idx.is_api_set("ext-ms-win-foo.dll"));
        assert!(!idx.is_api_set("ffmpeg.dll"));
    }
}
