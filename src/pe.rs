//! Minimal, read-only PE inspection.
//!
//! DLLH3x never writes, patches or executes anything. It parses the import
//! table and the delay-load import table of a PE on disk and computes an
//! imphash for triage. Nothing here produces or plants a module.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use goblin::pe::PE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    /// Bound at load time via the standard import directory.
    Normal,
    /// Resolved lazily via the delay-load import directory.
    Delay,
}

impl ImportKind {
    pub fn label(self) -> &'static str {
        match self {
            ImportKind::Normal => "import",
            ImportKind::Delay => "delay",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportedDll {
    pub name: String,
    pub kind: ImportKind,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub path: PathBuf,
    pub is_64: bool,
    pub machine: String,
    pub imphash: Option<String>,
    pub imports: Vec<ImportedDll>,
}

impl PeInfo {
    /// Parse a PE file from disk. Returns an error for non-PE inputs.
    pub fn parse(path: &Path) -> Result<PeInfo> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if bytes.len() < 2 || &bytes[0..2] != b"MZ" {
            return Err(anyhow!("not a PE/MZ image"));
        }
        let pe = PE::parse(&bytes).context("parsing PE headers")?;

        let mut dlls: Vec<ImportedDll> = Vec::new();

        // Normal imports: group goblin's flat symbol list by DLL, preserving
        // first-seen order so the imphash below stays deterministic.
        for imp in &pe.imports {
            let dll = imp.dll.to_string();
            let func = import_symbol(&imp.name, imp.ordinal);
            match dlls
                .iter_mut()
                .find(|d| d.kind == ImportKind::Normal && d.name.eq_ignore_ascii_case(&dll))
            {
                Some(entry) => entry.functions.push(func),
                None => dlls.push(ImportedDll {
                    name: dll,
                    kind: ImportKind::Normal,
                    functions: vec![func],
                }),
            }
        }

        // Delay-load imports: parsed from data directory #13. They are a
        // classic side-loading surface, so we track them as their own kind.
        for name in delay_load_names(&pe, &bytes) {
            if !dlls
                .iter()
                .any(|d| d.kind == ImportKind::Delay && d.name.eq_ignore_ascii_case(&name))
            {
                dlls.push(ImportedDll {
                    name,
                    kind: ImportKind::Delay,
                    functions: Vec::new(),
                });
            }
        }

        let imphash = compute_imphash(&pe);

        Ok(PeInfo {
            path: path.to_path_buf(),
            is_64: pe.is_64,
            machine: machine_string(pe.header.coff_header.machine),
            imphash,
            imports: dlls,
        })
    }
}

/// Render a single imported symbol the way imphash tooling expects: either the
/// function name or `ord<N>` for ordinal-only imports.
fn import_symbol(name: &str, ordinal: u16) -> String {
    if name.is_empty() {
        format!("ord{ordinal}")
    } else {
        name.to_string()
    }
}

/// Size of one `IMAGE_DELAYLOAD_DESCRIPTOR` (eight DWORDs).
const DELAY_DESCRIPTOR_SIZE: usize = 32;

/// Parse module names from the delay-load import directory (data directory #13).
///
/// Each descriptor's `DllNameRVA` points at the imported module's name. Modern
/// linkers emit RVA-based descriptors; we handle the (rare) VA-based form by
/// subtracting the image base. Parsing is defensive: any malformed or
/// out-of-bounds field simply ends the walk rather than erroring the scan.
fn delay_load_names(pe: &PE, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    let dir = match pe
        .header
        .optional_header
        .as_ref()
        .and_then(|oh| oh.data_directories.get_delay_import_descriptor())
    {
        Some(d) if d.virtual_address != 0 && d.size != 0 => *d,
        _ => return out,
    };

    let mut table_off = match rva_to_offset(pe, dir.virtual_address) {
        Some(o) => o,
        None => return out,
    };

    // Walk descriptors until a zero terminator or a parse failure.
    for _ in 0..1024 {
        let desc = match bytes.get(table_off..table_off + DELAY_DESCRIPTOR_SIZE) {
            Some(d) => d,
            None => break,
        };
        let attributes = read_u32(desc, 0);
        let name_field = read_u32(desc, 4);
        // All-zero descriptor terminates the table.
        if attributes == 0 && name_field == 0 {
            break;
        }

        // Bit 0 of Attributes (RVA-based) is set by modern toolchains. When it
        // is clear the field is a VA, so rebase it against the image base.
        let name_rva = if attributes & 0x1 != 0 {
            name_field
        } else {
            name_field.wrapping_sub(pe.image_base as u32)
        };

        if let Some(name_off) = rva_to_offset(pe, name_rva) {
            if let Some(name) = read_cstr(bytes, name_off) {
                if !name.is_empty() && !out.iter().any(|n: &String| n.eq_ignore_ascii_case(&name)) {
                    out.push(name);
                }
            }
        }

        table_off += DELAY_DESCRIPTOR_SIZE;
    }
    out
}

/// Map a relative virtual address to a file offset using the section table.
fn rva_to_offset(pe: &PE, rva: u32) -> Option<usize> {
    for section in &pe.sections {
        let va = section.virtual_address;
        let vsize = section.virtual_size.max(section.size_of_raw_data);
        if rva >= va && rva < va + vsize {
            let delta = rva - va;
            return Some(section.pointer_to_raw_data as usize + delta as usize);
        }
    }
    None
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let b = &buf[off..off + 4];
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Read a NUL-terminated ASCII string, capped to keep a corrupt file bounded.
fn read_cstr(bytes: &[u8], off: usize) -> Option<String> {
    let slice = bytes.get(off..)?;
    let end = slice.iter().take(256).position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Mandiant-style imphash: md5 over `dllstem.funcname` entries, lowercased,
/// comma-joined, in import-table order.
fn compute_imphash(pe: &PE) -> Option<String> {
    if pe.imports.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(pe.imports.len());
    for imp in &pe.imports {
        let dll = imp.dll.to_ascii_lowercase();
        let stem = dll
            .strip_suffix(".dll")
            .or_else(|| dll.strip_suffix(".ocx"))
            .or_else(|| dll.strip_suffix(".sys"))
            .unwrap_or(&dll);
        let func = import_symbol(&imp.name, imp.ordinal).to_ascii_lowercase();
        parts.push(format!("{stem}.{func}"));
    }
    let joined = parts.join(",");
    let digest = md5::compute(joined.as_bytes());
    Some(format!("{digest:x}"))
}

fn machine_string(machine: u16) -> String {
    match machine {
        0x014c => "x86 (i386)".to_string(),
        0x8664 => "x64 (AMD64)".to_string(),
        0x01c0 => "ARM".to_string(),
        0xaa64 => "ARM64".to_string(),
        0x0200 => "IA64".to_string(),
        other => format!("0x{other:04x}"),
    }
}
