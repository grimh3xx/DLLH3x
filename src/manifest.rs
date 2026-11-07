//! Side-by-side (SxS) / activation-context manifest parsing.
//!
//! A Windows application can carry a manifest — embedded as an `RT_MANIFEST`
//! resource or shipped as an external `<binary>.manifest` — that declares
//! dependent assemblies and private `<file>` entries. A declared `<file>`
//! redirects that module to the application directory via the activation
//! context (classic DotLocal / SxS redirection), so an import that looks like a
//! "phantom" may in fact be an *intended* app-local assembly.
//!
//! DLLH3x reads the manifest so it can tell the two apart — and still flag a
//! redirected module that sits in a writable directory. Parsing is a light,
//! dependency-free scan: manifests are small, uncompressed UTF-8 XML.

use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSource {
    /// Embedded `RT_MANIFEST` resource inside the PE.
    Embedded,
    /// External `<binary>.manifest` next to the PE.
    External,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Manifest {
    pub source: ManifestSource,
    /// Lowercased `<file name="...">` entries — modules redirected app-local.
    pub files: HashSet<String>,
    /// `<assemblyIdentity>` names inside `<dependency>` blocks (WinSxS assemblies).
    pub dependencies: Vec<String>,
}

impl Manifest {
    pub fn redirects(&self, dll: &str) -> bool {
        self.files.contains(&dll.to_ascii_lowercase())
    }
}

/// Locate and parse a manifest for `binary_path`, preferring an embedded one.
pub fn load(binary_path: &Path) -> Option<Manifest> {
    if let Ok(bytes) = std::fs::read(binary_path) {
        if let Some(xml) = extract_embedded_manifest(&bytes) {
            let (files, dependencies) = parse_manifest(&xml);
            if !files.is_empty() || !dependencies.is_empty() {
                return Some(Manifest {
                    source: ManifestSource::Embedded,
                    files,
                    dependencies,
                });
            }
        }
    }

    // External "<binary>.manifest" (e.g. app.exe.manifest).
    let external = append_ext(binary_path, "manifest");
    if let Ok(text) = std::fs::read_to_string(&external) {
        let (files, dependencies) = parse_manifest(&text);
        if !files.is_empty() || !dependencies.is_empty() {
            return Some(Manifest {
                source: ManifestSource::External,
                files,
                dependencies,
            });
        }
    }
    None
}

/// Find the embedded manifest XML in a PE by locating the SxS assembly element.
/// Manifests are stored as plain UTF-8 text in the resource section, so a
/// bounded text scan is reliable without walking the full resource tree.
fn extract_embedded_manifest(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let anchor = text.find("manifestVersion")?;
    // Back up to the enclosing "<assembly" open tag.
    let start = text[..anchor].rfind("<assembly")?;
    let rel_end = text[start..].find("</assembly>")?;
    let end = start + rel_end + "</assembly>".len();
    Some(text[start..end].to_string())
}

/// Pull `<file name>` and dependency identity names out of a manifest.
fn parse_manifest(xml: &str) -> (HashSet<String>, Vec<String>) {
    let mut files = HashSet::new();
    for tag in find_tags(xml, "<file") {
        if let Some(name) = attr(&tag, "name") {
            // A <file> name may carry a relative path; the loader keys on the
            // base file name, so index that.
            let base = name.rsplit(['\\', '/']).next().unwrap_or(&name);
            if !base.is_empty() {
                files.insert(base.to_ascii_lowercase());
            }
        }
    }

    // Dependency assembly identities live inside <dependency> blocks; the
    // top-level <assemblyIdentity> (the app's own identity) is excluded by
    // only scanning dependentAssembly chunks.
    let mut dependencies = Vec::new();
    for chunk in xml.split("<dependentAssembly").skip(1) {
        if let Some(open) = chunk.find("<assemblyIdentity") {
            let tag_end = chunk[open..]
                .find('>')
                .map(|i| open + i + 1)
                .unwrap_or(chunk.len());
            if let Some(name) = attr(&chunk[open..tag_end], "name") {
                if !dependencies
                    .iter()
                    .any(|d: &String| d.eq_ignore_ascii_case(&name))
                {
                    dependencies.push(name);
                }
            }
        }
    }
    (files, dependencies)
}

/// Collect every opening tag that starts with `prefix` (up to its `>`).
fn find_tags(xml: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(prefix) {
        let after = &rest[i..];
        if let Some(end) = after.find('>') {
            out.push(after[..=end].to_string());
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    out
}

/// Extract a quoted attribute value from a single tag string.
fn attr(tag: &str, key: &str) -> Option<String> {
    let mut search = tag;
    while let Some(i) = search.find(key) {
        let after = &search[i + key.len()..];
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix('=') {
            let rest = rest.trim_start();
            let quote = rest.chars().next()?;
            if quote == '"' || quote == '\'' {
                let val = &rest[1..];
                if let Some(end) = val.find(quote) {
                    return Some(val[..end].to_string());
                }
            }
        }
        search = &search[i + key.len()..];
    }
    None
}

/// Append an extra extension to a path (`app.exe` -> `app.exe.manifest`).
fn append_ext(path: &Path, ext: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
      <assemblyIdentity name="MyApp" version="1.0.0.0"/>
      <dependency><dependentAssembly>
        <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/>
      </dependentAssembly></dependency>
      <file name="plugin.dll"/>
      <file name="sub\helper.DLL"/>
    </assembly>"#;

    #[test]
    fn parses_files_and_dependencies() {
        let (files, deps) = parse_manifest(XML);
        assert!(files.contains("plugin.dll"));
        assert!(files.contains("helper.dll")); // base name, lowercased
        assert_eq!(deps, vec!["Microsoft.Windows.Common-Controls".to_string()]);
    }

    #[test]
    fn extracts_embedded_from_bytes() {
        let blob = format!("MZ\0\0garbage\0{XML}\0more");
        let got = extract_embedded_manifest(blob.as_bytes()).unwrap();
        assert!(got.contains("plugin.dll"));
        assert!(got.trim_end().ends_with("</assembly>"));
    }
}
