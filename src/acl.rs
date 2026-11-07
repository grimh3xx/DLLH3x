//! Install-directory write exposure.
//!
//! "Can an attacker drop a file here?" is the signal that turns a hijack
//! *candidate* into live exposure. DLLH3x answers it three ways, strongest
//! first:
//!
//!   1. **ACL principals** — on Windows, `icacls` is parsed to name the
//!      low-privilege identities (Users, Authenticated Users, Everyone) that
//!      hold write access. This is the report-grade signal.
//!   2. **Write probe** — a temp file is created and removed; a cheap ground
//!      truth that also works off-Windows.
//!   3. **DotLocal** — a `<binary>.local` file/dir forces app-local resolution
//!      for the whole process, a classic redirection surface.

use std::path::Path;

/// Low-privilege identities whose write access is noteworthy. Compared
/// case-insensitively against the account name `icacls` prints.
const RISKY_PRINCIPALS: &[&str] = &[
    "everyone",
    "builtin\\users",
    "users",
    "authenticated users",
    "nt authority\\authenticated users",
    "builtin\\authenticated users",
];

#[derive(Debug, Clone, Default)]
pub struct DirExposure {
    /// Temp-file write probe: Some(true)/Some(false), or None if inconclusive.
    pub writable: Option<bool>,
    /// Low-privilege principals with write access, from `icacls` (Windows).
    pub writers: Vec<String>,
}

impl DirExposure {
    /// A directory is considered exposed if a risky principal can write or the
    /// probe succeeded.
    pub fn is_exposed(&self) -> bool {
        !self.writers.is_empty() || self.writable == Some(true)
    }
}

/// Inspect a directory's write exposure.
pub fn inspect_dir(dir: &Path) -> DirExposure {
    DirExposure {
        writable: probe_writable(dir),
        writers: icacls_writers(dir),
    }
}

/// True if a `<binary>.local` redirection marker sits next to the binary.
pub fn has_dotlocal(binary: &Path) -> bool {
    let mut s = binary.as_os_str().to_os_string();
    s.push(".local");
    let p = std::path::PathBuf::from(s);
    p.exists()
}

/// Best-effort writability probe: create then remove a hidden temp file.
fn probe_writable(dir: &Path) -> Option<bool> {
    if !dir.is_dir() {
        return None;
    }
    let probe = dir.join(".dllh3x_write_probe.tmp");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Some(true)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Some(false)
            } else {
                None
            }
        }
    }
}

/// Parse `icacls <dir>` for low-privilege principals with write access.
/// Returns an empty vec off-Windows or when `icacls` is unavailable.
fn icacls_writers(dir: &Path) -> Vec<String> {
    let output = match std::process::Command::new("icacls").arg(dir).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_icacls(&text)
}

/// Extract write-capable risky principals from icacls output.
///
/// Each ACE line looks like `ACCOUNT:(flags)(rights)...`. We take the account
/// before the first `:(`, collect every parenthesised token, and treat the ACE
/// as write-capable if it grants Full, Modify, Write, or an advanced
/// write/append/delete data right.
fn parse_icacls(text: &str) -> Vec<String> {
    let mut writers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(colon) = line.find(":(") else {
            continue;
        };
        let account = line[..colon].trim();
        if account.is_empty() {
            continue;
        }
        let rights = &line[colon + 1..];
        if !grants_write(rights) {
            continue;
        }
        let low = account.to_ascii_lowercase();
        if RISKY_PRINCIPALS
            .iter()
            .any(|p| low == *p || low.ends_with(p))
        {
            let acct = account.to_string();
            if !writers
                .iter()
                .any(|w: &String| w.eq_ignore_ascii_case(&acct))
            {
                writers.push(acct);
            }
        }
    }
    writers
}

/// True if any parenthesised icacls right token implies write access.
fn grants_write(rights: &str) -> bool {
    for token in rights.split(['(', ')']) {
        let t = token.trim().to_ascii_uppercase();
        match t.as_str() {
            "F" | "M" | "W" => return true, // full, modify, write
            "WD" | "AD" | "WA" | "WEA" | "DC" => return true, // advanced write/append/delete-child
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_risky_writers() {
        let out = "C:\\App BUILTIN\\Administrators:(F)\n\
                   NT AUTHORITY\\SYSTEM:(F)\n\
                   BUILTIN\\Users:(OI)(CI)(M)\n\
                   NT AUTHORITY\\Authenticated Users:(RX)\n";
        let w = parse_icacls(out);
        assert_eq!(w, vec!["BUILTIN\\Users".to_string()]);
    }

    #[test]
    fn read_only_users_are_not_writers() {
        let out = "C:\\App BUILTIN\\Users:(OI)(CI)(RX)\n";
        assert!(parse_icacls(out).is_empty());
    }
}
