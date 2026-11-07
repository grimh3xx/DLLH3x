//! Transitive dependency-graph analysis.
//!
//! Most hijack scanners stop at a binary's *direct* imports. DLLH3x follows the
//! dependency tree through the modules that resolve **from the application
//! directory** — because those app-local modules have their *own* imports, also
//! resolved against the same directory, and can reach a phantom slot two or
//! three hops down that no direct scan would ever surface:
//!
//! ```text
//! app.exe
//!  └─ plugin.dll   (app-local, unsigned)
//!       └─ codec.dll   ← PHANTOM  (depth 2 — invisible to a direct scan)
//! ```
//!
//! Recursion only descends into app-local / shadowing / manifest-redirected
//! modules (system and KnownDLL modules resolve their own dependencies from the
//! protected system directory, so they are leaves here). A visited set and a
//! depth cap keep the walk bounded. Everything is read-only.

use std::collections::HashSet;
use std::path::Path;

use serde::Serialize;

use crate::manifest::Manifest;
use crate::pe::{ImportKind, PeInfo};
use crate::sysindex::SystemIndex;

/// Where the loader would resolve a module from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    ApiSet,
    Known,
    System,
    AppLocal,
    ManifestRedirected,
    Shadowing,
    Phantom,
}

impl Resolution {
    pub fn label(self) -> &'static str {
        match self {
            Resolution::ApiSet => "api-set",
            Resolution::Known => "known-dll",
            Resolution::System => "system",
            Resolution::AppLocal => "app-local",
            Resolution::ManifestRedirected => "manifest-redirected",
            Resolution::Shadowing => "shadowing",
            Resolution::Phantom => "phantom",
        }
    }
    /// A node that is itself a direct hijack point.
    fn is_hijack_point(self) -> bool {
        matches!(self, Resolution::Phantom | Resolution::Shadowing)
    }
    /// A node we descend into (it loads its own imports from the app directory).
    fn is_descendable(self) -> bool {
        matches!(
            self,
            Resolution::AppLocal | Resolution::ManifestRedirected | Resolution::Shadowing
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub name: String,
    pub resolution: Resolution,
    #[serde(rename = "import_kind")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

/// A root-to-hijack-point path discovered at depth >= 1 (i.e. reached *through*
/// at least one app-local module — the transitive finding a direct scan misses).
#[derive(Debug, Clone, Serialize)]
pub struct Chain {
    /// Module names from the first-level import down to the hijack point.
    pub path: Vec<String>,
    pub leaf: Resolution,
    pub depth: usize,
}

const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 4000;

struct Builder<'a> {
    index: &'a SystemIndex,
    is_64: bool,
    app_dir: &'a Path,
    app_dir_files: &'a HashSet<String>,
    manifest: Option<&'a Manifest>,
    nodes: usize,
}

/// Build the dependency tree rooted at `pe`'s direct imports.
pub fn build(
    pe: &PeInfo,
    index: &SystemIndex,
    app_dir: &Path,
    app_dir_files: &HashSet<String>,
    manifest: Option<&Manifest>,
) -> Vec<Node> {
    let mut b = Builder {
        index,
        is_64: pe.is_64,
        app_dir,
        app_dir_files,
        manifest,
        nodes: 0,
    };
    let mut visited = HashSet::new();
    visited.insert(file_stem_key(&pe.path));
    pe.imports
        .iter()
        .map(|imp| b.node(&imp.name, imp.kind, &mut visited, 0))
        .collect()
}

impl Builder<'_> {
    fn node(
        &mut self,
        name: &str,
        kind: ImportKind,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> Node {
        self.nodes += 1;
        let resolution = self.resolve(name);
        let lower = name.to_ascii_lowercase();

        let signed = if matches!(
            resolution,
            Resolution::AppLocal | Resolution::Shadowing | Resolution::ManifestRedirected
        ) {
            crate::pe::file_is_signed(&self.app_dir.join(name))
        } else {
            None
        };

        let mut children = Vec::new();
        // Descend into app-local modules we have not seen, within bounds.
        if resolution.is_descendable()
            && depth < MAX_DEPTH
            && self.nodes < MAX_NODES
            && !visited.contains(&lower)
        {
            visited.insert(lower.clone());
            if let Ok(child_pe) = PeInfo::parse(&self.app_dir.join(name)) {
                for imp in &child_pe.imports {
                    children.push(self.node(&imp.name, imp.kind, visited, depth + 1));
                }
            }
        }

        Node {
            name: name.to_string(),
            resolution,
            kind: kind.label(),
            signed,
            children,
        }
    }

    /// Resolve a module name to where the loader would find it. Mirrors the
    /// classification order used by the flat analysis.
    fn resolve(&self, name: &str) -> Resolution {
        if self.index.is_api_set(name) {
            Resolution::ApiSet
        } else if self.index.is_known_dll(name) {
            Resolution::Known
        } else if self.manifest.map(|m| m.redirects(name)).unwrap_or(false) {
            Resolution::ManifestRedirected
        } else {
            let present = self.app_dir_files.contains(&name.to_ascii_lowercase());
            let in_system = self.index.in_system(name, self.is_64);
            match (present, in_system) {
                (true, true) => Resolution::Shadowing,
                (true, false) => Resolution::AppLocal,
                (false, true) => Resolution::System,
                (false, false) => Resolution::Phantom,
            }
        }
    }
}

/// Extract every transitive hijack chain (a hijack point at depth >= 1).
pub fn chains(roots: &[Node]) -> Vec<Chain> {
    let mut out = Vec::new();
    for root in roots {
        let mut path = Vec::new();
        walk(root, &mut path, &mut out);
    }
    // Deepest and most-specific first.
    out.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.path.cmp(&b.path)));
    out
}

fn walk(node: &Node, path: &mut Vec<String>, out: &mut Vec<Chain>) {
    path.push(node.name.clone());
    // A hijack point reached through >= 1 app-local hop (depth index >= 1).
    if node.resolution.is_hijack_point() && path.len() > 1 {
        out.push(Chain {
            path: path.clone(),
            leaf: node.resolution,
            depth: path.len() - 1,
        });
    }
    for child in &node.children {
        walk(child, path, out);
    }
    path.pop();
}

/// Render the tree as an ASCII dependency graph.
pub fn render_tree(roots: &[Node]) -> String {
    let mut s = String::new();
    let n = roots.len();
    for (i, root) in roots.iter().enumerate() {
        render_node(root, "", i + 1 == n, &mut s);
    }
    s
}

fn render_node(node: &Node, prefix: &str, last: bool, out: &mut String) {
    let branch = if last { "└─ " } else { "├─ " };
    out.push_str(&format!(
        "{prefix}{branch}{}  [{}]\n",
        node.name,
        node.resolution.label()
    ));
    let child_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, &child_prefix, i + 1 == n, out);
    }
}

/// Render the graph as Graphviz DOT.
pub fn render_dot(target: &str, roots: &[Node]) -> String {
    let mut s = String::from("digraph dllh3x {\n  rankdir=LR;\n  node [shape=box,style=rounded,fontname=\"monospace\"];\n");
    let root_id = "n0";
    s.push_str(&format!(
        "  {root_id} [label=\"{}\",style=\"rounded,bold\"];\n",
        dot_escape(target)
    ));
    let mut counter = 1usize;
    for root in roots {
        emit_dot(root, root_id, &mut counter, &mut s);
    }
    s.push_str("}\n");
    s
}

fn emit_dot(node: &Node, parent_id: &str, counter: &mut usize, out: &mut String) {
    let id = format!("n{}", *counter);
    *counter += 1;
    let color = match node.resolution {
        Resolution::Phantom => "#FF5F57",
        Resolution::Shadowing => "#FEBC2E",
        Resolution::AppLocal | Resolution::ManifestRedirected => "#60A5FA",
        _ => "#8795A8",
    };
    out.push_str(&format!(
        "  {id} [label=\"{}\\n[{}]\",color=\"{color}\"];\n",
        dot_escape(&node.name),
        node.resolution.label()
    ));
    out.push_str(&format!("  {parent_id} -> {id};\n"));
    for child in &node.children {
        emit_dot(child, &id, counter, out);
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn file_stem_key(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str, r: Resolution, children: Vec<Node>) -> Node {
        Node {
            name: name.to_string(),
            resolution: r,
            kind: "import",
            signed: None,
            children,
        }
    }

    #[test]
    fn finds_deep_chain() {
        // app.exe -> plugin.dll (app-local) -> codec.dll (phantom)
        let roots = vec![leaf(
            "plugin.dll",
            Resolution::AppLocal,
            vec![leaf("codec.dll", Resolution::Phantom, vec![])],
        )];
        let c = chains(&roots);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].path, vec!["plugin.dll", "codec.dll"]);
        assert_eq!(c[0].depth, 1);
        assert_eq!(c[0].leaf, Resolution::Phantom);
    }

    #[test]
    fn direct_phantom_is_not_a_transitive_chain() {
        // A depth-0 phantom is already a flat finding, not a transitive chain.
        let roots = vec![leaf("codec.dll", Resolution::Phantom, vec![])];
        assert!(chains(&roots).is_empty());
    }
}
