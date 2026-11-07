//! Alternate report renderings: SARIF 2.1.0 and a self-contained HTML page.

use serde_json::json;

use crate::analysis::{Classification, Finding, Report, Risk};

const TOOL_URI: &str = "https://github.com/grimh3xx/DLLH3x";

/// SARIF severity level for a risk. `Info` maps to `note` as well so nothing is
/// silently dropped, but callers typically filter info out beforehand.
fn sarif_level(r: Risk) -> &'static str {
    match r {
        Risk::Critical | Risk::High => "error",
        Risk::Medium => "warning",
        Risk::Low | Risk::Info => "note",
    }
}

fn rule_id(c: Classification) -> &'static str {
    match c {
        Classification::PhantomDll => "phantom-dll",
        Classification::ShadowingDll => "shadowing-dll",
        Classification::ManifestRedirected => "manifest-redirected",
        Classification::AppLocalDll => "app-local-dll",
        Classification::SystemDll => "system-dll",
        Classification::KnownDll => "known-dll",
        Classification::ApiSet => "api-set",
    }
}

/// Render a batch of reports as SARIF 2.1.0 (findings at `low`+ only).
pub fn to_sarif(reports: &[Report], version: &str) -> String {
    let rules = json!([
        rule("phantom-dll", "Phantom DLL (search-order hijack)", "An imported module is absent from the system directory and the application directory, leaving a slot an attacker can fill.", "T1574.001"),
        rule("shadowing-dll", "App-local module shadows a system DLL", "A module next to the binary shadows a System32 module of the same name.", "T1574.001"),
        rule("manifest-redirected", "SxS manifest redirected module", "A module is pinned app-local by an activation-context manifest <file> entry.", "T1574.002"),
        rule("app-local-dll", "App-local module", "A private module shipped next to the binary.", "T1574.002"),
        rule("transitive-hijack-chain", "Transitive hijack chain", "A phantom/shadowing slot reachable through one or more app-local modules.", "T1574.001"),
    ]);

    let mut results: Vec<serde_json::Value> = Vec::new();
    for report in reports {
        let uri = path_to_uri(&report.target);
        for f in &report.findings {
            if f.risk < Risk::Low {
                continue;
            }
            results.push(finding_result(f, &uri, &report.target));
        }
        for ch in &report.transitive_chains {
            let msg = format!(
                "Transitive hijack chain (depth {}): {} resolves {} through an app-local module.",
                ch.depth,
                ch.path.join(" → "),
                ch.leaf.label()
            );
            results.push(json!({
                "ruleId": "transitive-hijack-chain",
                "level": "error",
                "message": { "text": msg },
                "locations": [ location(&uri) ],
                "properties": { "path": ch.path, "depth": ch.depth, "leaf": ch.leaf.label() }
            }));
        }
    }

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "DLLH3x",
                "version": version,
                "informationUri": TOOL_URI,
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn rule(id: &str, name: &str, desc: &str, attack: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "shortDescription": { "text": name },
        "fullDescription": { "text": desc },
        "helpUri": TOOL_URI,
        "defaultConfiguration": { "level": "warning" },
        "properties": { "tags": ["security", "dll-hijacking", attack] }
    })
}

fn finding_result(f: &Finding, uri: &str, target: &str) -> serde_json::Value {
    let text = format!(
        "{} [{}] ({}) — exploitability {:.2} ({}){}",
        f.dll,
        f.classification.label(),
        f.kind,
        f.exploitability,
        f.confidence,
        if f.attack.is_empty() {
            String::new()
        } else {
            format!(" — ATT&CK {}", f.attack.join(", "))
        }
    );
    json!({
        "ruleId": rule_id(f.classification),
        "level": sarif_level(f.risk),
        "message": { "text": text },
        "locations": [ location(uri) ],
        "partialFingerprints": {
            "dllh3x/v1": fingerprint(target, &f.dll, f.classification.label())
        },
        "properties": {
            "risk": f.risk.label(),
            "classification": f.classification.label(),
            "exploitability": f.exploitability,
            "confidence": f.confidence,
            "attack": f.attack,
            "signed": f.signed,
        }
    })
}

fn location(uri: &str) -> serde_json::Value {
    json!({ "physicalLocation": { "artifactLocation": { "uri": uri } } })
}

fn path_to_uri(p: &str) -> String {
    p.replace('\\', "/")
}

fn fingerprint(target: &str, dll: &str, class: &str) -> String {
    let digest = md5::compute(format!("{target}|{dll}|{class}").as_bytes());
    format!("{digest:x}")
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render a self-contained HTML report in the house theme.
pub fn to_html(reports: &[Report], version: &str) -> String {
    let mut body = String::new();
    for report in reports {
        body.push_str(&html_report(report));
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>DLLH3x report</title>{CSS}</head><body>\
<header><span class=\"dot\"></span> <b>DLLH3x</b> <span class=\"muted\">· read-only DLL hijack auditor · v{version}</span></header>\
<main>{body}</main>\
<footer class=\"muted\">Generated by DLLH3x — diagnosis only, no exploitation. {TOOL_URI}</footer>\
</body></html>"
    )
}

fn html_report(r: &Report) -> String {
    let writers = if r.app_dir_writers.is_empty() {
        match r.app_dir_writable {
            Some(true) => "writable".to_string(),
            Some(false) => "not writable".to_string(),
            None => "unknown".to_string(),
        }
    } else {
        format!("writable by {}", esc(&r.app_dir_writers.join(", ")))
    };
    let sig = if r.target_signed {
        "signed"
    } else {
        "unsigned"
    };

    let mut rows = String::new();
    for f in &r.findings {
        if f.risk < Risk::Low {
            continue;
        }
        let rc = risk_class(f.risk);
        rows.push_str(&format!(
            "<tr><td><span class=\"badge {rc}\">{}</span></td>\
<td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
<td class=\"mono\">{:.2} <span class=\"muted\">{}</span></td>\
<td class=\"mono\">{}</td><td>{}</td></tr>",
            f.risk.label(),
            esc(&f.dll),
            f.classification.label(),
            f.kind,
            f.exploitability,
            f.confidence,
            if f.attack.is_empty() {
                "—".to_string()
            } else {
                esc(&f.attack.join(", "))
            },
            esc(f.reasons.first().map(|s| s.as_str()).unwrap_or("")),
        ));
    }

    let mut chains = String::new();
    if !r.transitive_chains.is_empty() {
        chains.push_str("<h3>Transitive hijack chains</h3><ul class=\"chains\">");
        for ch in &r.transitive_chains {
            chains.push_str(&format!(
                "<li class=\"mono\">{} <span class=\"muted\">[{}, depth {}]</span></li>",
                esc(&ch.path.join(" → ")),
                ch.leaf.label(),
                ch.depth
            ));
        }
        chains.push_str("</ul>");
    }

    let c = &r.counts;
    format!(
        "<section class=\"card\"><h2 class=\"mono\">{target}</h2>\
<div class=\"meta\">{arch} · imphash {imphash} · image {sig} · app dir: {writers}</div>\
<div class=\"score\"><div class=\"bar\"><div class=\"fill {sc}\" style=\"width:{score}%\"></div></div>\
<span class=\"mono\">{score}/100</span></div>\
<div class=\"counts\"><span class=\"badge crit\">crit {crit}</span>\
<span class=\"badge high\">high {high}</span><span class=\"badge med\">med {med}</span>\
<span class=\"badge low\">low {low}</span><span class=\"badge info\">info {info}</span></div>\
<table><thead><tr><th>risk</th><th>module</th><th>class</th><th>kind</th>\
<th>exploit</th><th>att&amp;ck</th><th>why</th></tr></thead><tbody>{rows}</tbody></table>\
{chains}</section>",
        target = esc(&r.target),
        arch = esc(&r.arch),
        imphash = esc(r.imphash.as_deref().unwrap_or("-")),
        sig = sig,
        writers = writers,
        sc = score_class(r.surface_score),
        score = r.surface_score,
        crit = c.critical,
        high = c.high,
        med = c.medium,
        low = c.low,
        info = c.info,
        rows = rows,
        chains = chains,
    )
}

fn risk_class(r: Risk) -> &'static str {
    match r {
        Risk::Critical => "crit",
        Risk::High => "high",
        Risk::Medium => "med",
        Risk::Low => "low",
        Risk::Info => "info",
    }
}

fn score_class(s: u32) -> &'static str {
    match s {
        85..=100 => "crit",
        55..=84 => "high",
        25..=54 => "med",
        _ => "low",
    }
}

const CSS: &str = "<style>\
:root{--bg:#0d1117;--panel:#111826;--border:#1e2a3d;--text:#d5dde8;--muted:#8795a8;\
--cyan:#22d3ee;--blue:#60a5fa;--red:#ff5f57;--amber:#febc2e;--green:#28c840}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);\
font-family:ui-sans-serif,system-ui,'Segoe UI',Arial,sans-serif;font-size:14px}\
.mono{font-family:ui-monospace,Consolas,Menlo,monospace}.muted{color:var(--muted)}\
header{padding:16px 24px;border-bottom:1px solid var(--border);background:var(--panel)}\
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--cyan)}\
main{padding:24px;max-width:1100px;margin:0 auto}footer{padding:16px 24px;border-top:1px solid var(--border)}\
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:24px}\
h2{margin:0 0 4px;font-size:16px;word-break:break-all}.meta{color:var(--muted);margin-bottom:14px}\
.score{display:flex;align-items:center;gap:10px;margin-bottom:12px}\
.bar{flex:1;height:10px;background:#0b0f17;border-radius:6px;overflow:hidden}\
.fill{height:100%}.fill.crit{background:var(--red)}.fill.high{background:var(--red)}\
.fill.med{background:var(--amber)}.fill.low{background:var(--green)}\
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}\
.badge{font-family:ui-monospace,monospace;font-size:12px;padding:2px 8px;border-radius:6px;\
border:1px solid var(--border);color:var(--text)}\
.badge.crit{background:var(--red);color:#fff;border-color:transparent}\
.badge.high{color:var(--red)}.badge.med{color:var(--amber)}.badge.low{color:var(--blue)}.badge.info{color:var(--muted)}\
table{width:100%;border-collapse:collapse;margin-top:8px}\
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}\
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}\
.chains{list-style:none;padding:0}.chains li{padding:6px 0}\
h3{font-size:14px;margin:18px 0 8px}\
</style>";
