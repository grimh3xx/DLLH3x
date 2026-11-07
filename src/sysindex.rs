//! System module index.
//!
//! DLLH3x needs to know, for any imported module name, whether Windows would
//! resolve it from a protected/system location (and therefore NOT from the
//! application directory). Three buckets matter:
//!
//!   * **KnownDLLs**  — mapped from the `\KnownDlls` object directory; always
//!     loaded from the system directory, immune to search-order hijacking.
//!   * **API sets**   — `api-ms-win-*` / `ext-ms-*`; resolved by the API-set
//!     schema, never from disk next to the binary.
//!   * **System dir** — present under System32 (64-bit) or SysWOW64 (32-bit);
//!     under SafeDllSearchMode these resolve from the system directory.
//!
//! The *bitness of the target* decides which system directory the loader uses:
//! a 32-bit (x86) image on 64-bit Windows resolves its system DLLs from
//! **SysWOW64**, not System32. The index therefore keeps both sets and picks
//! the right one per binary. A module that is in none of the buckets is an
//! application-supplied dependency and is a search-order hijack candidate.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Embedded fallbacks, used only when no live system directory is available.
const KNOWN_DLLS_TXT: &str = include_str!("../data/knowndlls.txt");
const SYSTEM32_BASELINE_TXT: &str = include_str!("../data/system32_baseline.txt");

/// How a system-module set was sourced. Reported so a reader never mistakes
/// a baseline guess for ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexSource {
    /// Read from a real system directory (Windows, or via a `--*-root` flag).
    Live,
    /// Built-in baseline list (running off-Windows, no system root given).
    Baseline,
}

/// The module set for one system directory (System32 or SysWOW64).
pub struct ArchIndex {
    dlls: HashSet<String>, // lowercase file names, with extension
    pub source: IndexSource,
    pub root: Option<PathBuf>,
}

impl ArchIndex {
    fn baseline() -> Self {
        ArchIndex {
            dlls: parse_lines(SYSTEM32_BASELINE_TXT),
            source: IndexSource::Baseline,
            root: None,
        }
    }
    pub fn len(&self) -> usize {
        self.dlls.len()
    }
    /// Present to satisfy clippy's `len_without_is_empty`; kept for API symmetry.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }
    pub fn contains(&self, name: &str) -> bool {
        self.dlls.contains(&name.to_ascii_lowercase())
    }
    pub fn dir_label(&self) -> Option<String> {
        self.root.as_deref().map(|p| p.display().to_string())
    }
}

pub struct SystemIndex {
    known_dlls: HashSet<String>, // lowercase, no extension
    /// Resolution set for 64-bit targets (System32).
    system32: ArchIndex,
    /// Resolution set for 32-bit targets (SysWOW64). `None` falls back to
    /// `system32` — the module names overlap heavily, so this stays usable
    /// off-Windows, and callers can see it was not a true WoW64 index.
    syswow64: Option<ArchIndex>,
}

impl SystemIndex {
    /// Build the index.
    ///
    /// `system_root` / `wow64_root` point at live System32 / SysWOW64
    /// directories (e.g. `/mnt/c/Windows/System32` from WSL). When omitted, on
    /// Windows the real directories are read; otherwise System32 falls back to
    /// the built-in baseline and SysWOW64 is left unresolved.
    pub fn load(system_root: Option<&Path>, wow64_root: Option<&Path>) -> Self {
        let known_dlls = parse_lines(KNOWN_DLLS_TXT);

        // --- System32 (64-bit target resolution) ---
        let system32 = live_arch(system_root)
            .or_else(default_system32_index)
            .unwrap_or_else(ArchIndex::baseline);

        // --- SysWOW64 (32-bit target resolution) ---
        let syswow64 = live_arch(wow64_root).or_else(default_syswow64_index);

        SystemIndex {
            known_dlls,
            system32,
            syswow64,
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

    /// The system-directory index the loader would use for a target of this
    /// bitness. A 32-bit target prefers SysWOW64 when available.
    pub fn arch_index(&self, is_64: bool) -> &ArchIndex {
        if !is_64 {
            if let Some(w) = &self.syswow64 {
                return w;
            }
        }
        &self.system32
    }

    /// True if the module exists in the system directory for this bitness.
    /// (Convenience wrapper over [`arch_index`]; exercised by the tests.)
    #[allow(dead_code)]
    pub fn in_system(&self, name: &str, is_64: bool) -> bool {
        self.arch_index(is_64).contains(name)
    }

    pub fn known_count(&self) -> usize {
        self.known_dlls.len()
    }
    pub fn system32(&self) -> &ArchIndex {
        &self.system32
    }
    pub fn syswow64(&self) -> Option<&ArchIndex> {
        self.syswow64.as_ref()
    }
}

fn parse_lines(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// Build a live [`ArchIndex`] from a directory, if it can be read.
fn live_arch(root: Option<&Path>) -> Option<ArchIndex> {
    let root = root?;
    let dlls = read_system_dir(root)?;
    Some(ArchIndex {
        dlls,
        source: IndexSource::Live,
        root: Some(root.to_path_buf()),
    })
}

/// Index every file name directly under a System32-like directory.
///
/// The loader resolves an import by its exact file name, and modules are
/// imported under several extensions (`.dll`, `.drv`, `.cpl`, `.ocx`, ...), so
/// we index all names rather than filter by extension and risk false phantoms.
fn read_system_dir(root: &Path) -> Option<HashSet<String>> {
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
fn windows_root() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root)
}

#[cfg(windows)]
fn default_system32_index() -> Option<ArchIndex> {
    live_arch(Some(&windows_root().join("System32")))
}

#[cfg(windows)]
fn default_syswow64_index() -> Option<ArchIndex> {
    live_arch(Some(&windows_root().join("SysWOW64")))
}

#[cfg(not(windows))]
fn default_system32_index() -> Option<ArchIndex> {
    None
}

#[cfg(not(windows))]
fn default_syswow64_index() -> Option<ArchIndex> {
    None
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
        let idx = SystemIndex::load(None, None);
        assert!(idx.is_known_dll("KERNEL32.dll"));
        assert!(idx.is_known_dll("ntdll"));
        assert!(idx.is_api_set("api-ms-win-core-synch-l1-2-0.dll"));
        assert!(idx.is_api_set("ext-ms-win-foo.dll"));
        assert!(!idx.is_api_set("ffmpeg.dll"));
    }

    // Off-Windows only: on Windows `load` reads the real System32/SysWOW64,
    // so there IS a live WoW64 index and this fallback path does not apply.
    #[cfg(not(windows))]
    #[test]
    fn falls_back_to_system32_when_no_wow64() {
        // With no live dirs, 32-bit queries must still resolve via the
        // baseline System32 set rather than panicking or missing everything.
        let idx = SystemIndex::load(None, None);
        assert!(idx.syswow64().is_none());
        assert!(idx.in_system("kernel32.dll", false));
        assert!(idx.in_system("kernel32.dll", true));
    }
}
