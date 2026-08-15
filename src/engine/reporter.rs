use crate::engine::issue::{Issue, Severity};
use crate::safety::audit::AuditEntry;
use colored::*;
use std::path::Path;

pub struct DiagnosticReporter;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl DiagnosticReporter {
    /// Print a styled banner in CLI mode
    pub fn print_banner() {
        println!(
            "{}",
            r#"
  ██╗    ██╗██╗███╗   ██╗███╗   ███╗███████╗██████╗ ██╗ ██████╗
  ██║    ██║██║████╗  ██║████╗ ████║██╔════╝██╔══██╗██║██╔════╝
  ██║ █╗ ██║██║██╔██╗ ██║██╔████╔██║█████╗  ██║  ██║██║██║     
  ██║███╗██║██║██║╚██╗██║██║╚██╔╝██║██╔══╝  ██║  ██║██║██║     
  ╚███╔███╔╝██║██║ ╚████║██║ ╚═╝ ██║███████╗██████╔╝██║╚██████╗
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝ ╚═════╝
           ─── ADVANCED PC DIAGNOSTICS & AUTO-REPAIR ───
"#
            .cyan()
            .bold()
        );
    }

    /// Print issues formatted in CLI console
    pub fn print_cli_report(issues: &[Issue], health_score: u8) {
        println!("\n{}", "═══ WINMEDIC DIAGNOSTIC REPORT ═══".cyan().bold());
        println!(
            "Overall health score: {}/100",
            if health_score >= 80 {
                format!("{}", health_score).green().bold()
            } else if health_score >= 50 {
                format!("{}", health_score).yellow().bold()
            } else {
                format!("{}", health_score).red().bold()
            }
        );
        println!("Issues found: {}\n", issues.len());

        if issues.is_empty() {
            println!(
                "{}",
                "No issues found. Your system is in excellent shape."
                    .green()
                    .bold()
            );
            return;
        }

        for (idx, issue) in issues.iter().enumerate() {
            let sev_str = match issue.severity {
                Severity::Critical => "[CRITICAL]".red().bold(),
                Severity::Warning => "[WARNING]".yellow().bold(),
                Severity::Info => "[INFO]".cyan(),
            };

            let status_str = if issue.is_fixed {
                "[FIXED]".green().bold()
            } else {
                "[OPEN]".white()
            };

            println!(
                "{}. {} {} {} - {}",
                idx + 1,
                sev_str,
                status_str,
                issue.category.magenta().bold(),
                issue.title.bold()
            );
            println!("   └─ {}", issue.description);
            println!("      Recommended fix: {}", issue.recommended_fix.green());
            println!();
        }
    }

    /// Generate JSON representation with metadata, findings, and audit history.
    pub fn to_json(issues: &[Issue], health_score: u8, audit_entries: &[AuditEntry]) -> String {
        #[derive(serde::Serialize)]
        struct Report<'a> {
            version: &'static str,
            timestamp: String,
            hostname: String,
            health_score: u8,
            issues_count: usize,
            issues: &'a [Issue],
            audit_entries: &'a [AuditEntry],
        }

        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "Windows PC".to_string());

        let rep = Report {
            version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Local::now().to_rfc3339(),
            hostname,
            health_score,
            issues_count: issues.len(),
            issues,
            audit_entries,
        };

        serde_json::to_string_pretty(&rep).unwrap_or_else(|_| "{}".to_string())
    }

    /// Export report as Markdown.
    pub fn to_markdown(issues: &[Issue], health_score: u8, audit_entries: &[AuditEntry]) -> String {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "Windows PC".to_string());

        let crit_count = issues
            .iter()
            .filter(|i| i.severity == Severity::Critical)
            .count();
        let warn_count = issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .count();
        let info_count = issues
            .iter()
            .filter(|i| i.severity == Severity::Info)
            .count();
        let fixed_count = issues.iter().filter(|i| i.is_fixed).count();
        let open_count = issues.len().saturating_sub(fixed_count);

        let mut md = format!(
            "# WinMedic Diagnostic & System Report\n\n\
            - **System:** {}\n\
            - **Generated:** {}\n\
            - **Health score:** {}/100\n\
            - **Issues found:** {} (critical: {}, warnings: {}, informational: {})\n\
            - **Status:** {} fixed, {} open\n\n\
            ---\n\n\
            ## Findings\n\n",
            hostname,
            timestamp,
            health_score,
            issues.len(),
            crit_count,
            warn_count,
            info_count,
            fixed_count,
            open_count
        );

        if issues.is_empty() {
            md.push_str("**No issues found.** The system is in excellent shape.\n\n");
        } else {
            for (idx, issue) in issues.iter().enumerate() {
                let sev_str = match issue.severity {
                    Severity::Critical => "[!] CRITICAL",
                    Severity::Warning => "[!] WARNING",
                    Severity::Info => "[i] INFO",
                };
                let status_str = if issue.is_fixed {
                    "[FIXED]"
                } else if issue.fix_error.is_some() {
                    "[FAILED]"
                } else {
                    "[OPEN]"
                };

                md.push_str(&format!(
                    "### {}. {} [{}] {}\n\n\
                    - **Category:** {}\n\
                    - **Module:** {}\n\
                    - **Risk level:** {}\n\
                    - **Status:** {}\n\
                    - **Description:** {}\n\n\
                    **Technical details:**\n```\n{}\n```\n\n\
                    **Recommended fix:** {}\n\n",
                    idx + 1,
                    sev_str,
                    status_str,
                    issue.title,
                    issue.category,
                    issue.module_id,
                    issue.risk_score.badge(),
                    status_str,
                    issue.description,
                    issue.technical_details,
                    issue.recommended_fix
                ));

                if let Some(ref err) = issue.fix_error {
                    md.push_str(&format!("> **Repair error:** {}\n\n", err));
                }

                if !issue.fix_steps.is_empty() {
                    md.push_str("**Planned steps:**\n");
                    for (s_idx, step) in issue.fix_steps.iter().enumerate() {
                        md.push_str(&format!("{}. {}\n", s_idx + 1, step));
                    }
                    md.push('\n');
                }
            }
        }

        if !audit_entries.is_empty() {
            md.push_str("---\n\n## Audit & Repair Log\n\n");
            md.push_str("| Time | Action | Module | Title | Status | Details |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for entry in audit_entries {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    entry.timestamp,
                    entry.action_type,
                    entry.module_id,
                    entry.title,
                    entry.status,
                    entry.details
                ));
            }
            md.push('\n');
        }

        md.push_str(&format!(
            "---\n*Generated with WinMedic v{}*\n",
            env!("CARGO_PKG_VERSION")
        ));

        md
    }

    /// Export report as a self-contained, responsive HTML file.
    pub fn to_html(issues: &[Issue], health_score: u8, audit_entries: &[AuditEntry]) -> String {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "Windows PC".to_string());

        let crit_count = issues
            .iter()
            .filter(|i| i.severity == Severity::Critical)
            .count();
        let warn_count = issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .count();
        let fixed_count = issues.iter().filter(|i| i.is_fixed).count();
        let open_count = issues.len().saturating_sub(fixed_count);

        let health_color = if health_score >= 80 {
            "#10b981" // Emerald
        } else if health_score >= 50 {
            "#f59e0b" // Amber
        } else {
            "#ef4444" // Coral Red
        };

        let mut issues_html = String::new();
        if issues.is_empty() {
            issues_html.push_str(
                r#"
            <div class="empty-state">
                <div class="empty-icon">[OK]</div>
                <h3>No issues found</h3>
                <p>Your Windows system is in excellent, clean shape.</p>
            </div>
            "#,
            );
        } else {
            for (idx, issue) in issues.iter().enumerate() {
                let (sev_class, sev_label) = match issue.severity {
                    Severity::Critical => ("badge-crit", "CRITICAL"),
                    Severity::Warning => ("badge-warn", "WARNING"),
                    Severity::Info => ("badge-info", "INFO"),
                };

                let (status_class, status_label) = if issue.is_fixed {
                    ("status-fixed", "FIXED")
                } else if issue.fix_error.is_some() {
                    ("status-failed", "FAILED")
                } else {
                    ("status-open", "OPEN")
                };

                let mut steps_html = String::new();
                if !issue.fix_steps.is_empty() {
                    steps_html.push_str(
                        "<div class=\"steps-title\">Planned steps:</div><ol class=\"steps-list\">",
                    );
                    for step in &issue.fix_steps {
                        steps_html.push_str(&format!("<li>{}</li>", escape_html(step)));
                    }
                    steps_html.push_str("</ol>");
                }

                let fix_error_html = if let Some(ref err) = issue.fix_error {
                    format!(
                        "<div class=\"error-banner\"><strong>Repair error:</strong> {}</div>",
                        escape_html(err)
                    )
                } else {
                    String::new()
                };

                issues_html.push_str(&format!(
                    r#"
                    <div class="card issue-card">
                        <div class="issue-header">
                            <div class="issue-title-group">
                                <span class="issue-number">#{idx}</span>
                                <span class="badge {sev_class}">{sev_label}</span>
                                <span class="badge badge-cat">{cat}</span>
                                <span class="issue-title">{title}</span>
                            </div>
                            <span class="status-pill {status_class}">{status_label}</span>
                        </div>
                        <div class="issue-body">
                            <p class="issue-desc">{desc}</p>
                            {fix_err}
                            <div class="section-label">Technical details:</div>
                            <pre class="tech-details"><code>{tech}</code></pre>
                            <div class="fix-box">
                                <div class="fix-title">Recommended repair:</div>
                                <div class="fix-text">{fix}</div>
                                {steps}
                            </div>
                        </div>
                    </div>
                    "#,
                    idx = idx + 1,
                    sev_class = sev_class,
                    sev_label = sev_label,
                    cat = escape_html(&issue.category),
                    title = escape_html(&issue.title),
                    status_class = status_class,
                    status_label = status_label,
                    desc = escape_html(&issue.description),
                    fix_err = fix_error_html,
                    tech = escape_html(&issue.technical_details),
                    fix = escape_html(&issue.recommended_fix),
                    steps = steps_html,
                ));
            }
        }

        let mut audit_html = String::new();
        if !audit_entries.is_empty() {
            let mut rows = String::new();
            for entry in audit_entries {
                let status_badge = match entry.status.as_str() {
                    "SUCCESS" => "<span class=\"badge badge-success\">SUCCESS</span>",
                    "FAILED" => "<span class=\"badge badge-crit\">FAILED</span>",
                    "WARNING" => "<span class=\"badge badge-warn\">WARNING</span>",
                    "DRYRUN" => "<span class=\"badge badge-warn\">DRYRUN</span>",
                    _ => "<span class=\"badge badge-info\">INFO</span>",
                };
                rows.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><span class=\"badge badge-cat\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td class=\"text-muted\">{}</td></tr>",
                    escape_html(&entry.timestamp),
                    escape_html(&entry.action_type),
                    escape_html(&entry.module_id),
                    escape_html(&entry.title),
                    status_badge,
                    escape_html(&entry.details)
                ));
            }
            audit_html = format!(
                r#"
                <section class="section">
                    <h2 class="section-heading">Audit &amp; Repair Log</h2>
                    <div class="card table-card">
                        <table class="audit-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Action</th>
                                    <th>Module</th>
                                    <th>Title</th>
                                    <th>Status</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </section>
                "#,
                rows
            );
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinMedic Diagnostic Report – {hostname}</title>
    <style>
        :root {{
            --bg-deep: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #24344d;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --cyan: #00d2ff;
            --emerald: #10b981;
            --coral: #ef4444;
            --amber: #f59e0b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-deep);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 32px 16px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 32px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            font-size: 32px;
        }}
        h1 {{
            font-size: 26px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.5px;
        }}
        .meta-text {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .health-badge-container {{
            display: flex;
            align-items: center;
            gap: 16px;
            background: var(--bg-card);
            padding: 12px 24px;
            border-radius: 12px;
            border: 1px solid var(--border);
        }}
        .health-score {{
            font-size: 36px;
            font-weight: 800;
            color: {health_color};
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .stat-val {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
        }}
        .stat-label {{
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .val-crit {{ color: var(--coral); }}
        .val-warn {{ color: var(--amber); }}
        .val-fixed {{ color: var(--emerald); }}
        .val-cyan {{ color: var(--cyan); }}
        .section {{
            margin-bottom: 40px;
        }}
        .section-heading {{
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 16px;
        }}
        .issue-card {{
            border-left: 4px solid var(--border);
            transition: background-color 0.15s ease;
        }}
        .issue-card:hover {{
            background-color: var(--bg-card-hover);
        }}
        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 14px;
        }}
        .issue-title-group {{
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .issue-number {{
            font-weight: 700;
            color: var(--text-muted);
            font-size: 14px;
        }}
        .issue-title {{
            font-size: 17px;
            font-weight: 600;
            color: var(--text-main);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }}
        .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: var(--coral); border: 1px solid var(--coral); }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.2); color: var(--amber); border: 1px solid var(--amber); }}
        .badge-info {{ background: rgba(0, 210, 255, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }}
        .badge-cat {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--emerald); border: 1px solid var(--emerald); }}
        .status-pill {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
        }}
        .status-fixed {{ background: rgba(16, 185, 129, 0.2); color: var(--emerald); }}
        .status-failed {{ background: rgba(239, 68, 68, 0.2); color: var(--coral); }}
        .status-open {{ background: rgba(148, 163, 184, 0.2); color: var(--text-muted); }}
        .issue-desc {{
            font-size: 15px;
            color: #cbd5e1;
            margin-bottom: 14px;
        }}
        .error-banner {{
            background: rgba(239, 68, 68, 0.15);
            border-left: 3px solid var(--coral);
            padding: 10px 14px;
            border-radius: 6px;
            color: var(--coral);
            font-size: 14px;
            margin-bottom: 14px;
        }}
        .section-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            font-weight: 600;
            margin-bottom: 6px;
        }}
        .tech-details {{
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 13px;
            color: #38bdf8;
            overflow-x: auto;
            margin-bottom: 14px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .fix-box {{
            background: rgba(0, 210, 255, 0.05);
            border: 1px solid rgba(0, 210, 255, 0.2);
            border-radius: 8px;
            padding: 14px;
        }}
        .fix-title {{
            font-weight: 700;
            color: var(--cyan);
            font-size: 14px;
            margin-bottom: 4px;
        }}
        .fix-text {{
            color: var(--text-main);
            font-size: 14px;
            margin-bottom: 8px;
        }}
        .steps-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            margin-top: 8px;
            margin-bottom: 4px;
        }}
        .steps-list {{
            padding-left: 20px;
            font-size: 13px;
            color: #cbd5e1;
        }}
        .steps-list li {{
            margin-bottom: 2px;
        }}
        .empty-state {{
            text-align: center;
            padding: 48px 24px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
        }}
        .empty-icon {{
            font-size: 48px;
            color: var(--emerald);
            margin-bottom: 12px;
        }}
        .table-card {{
            padding: 0;
            overflow-x: auto;
        }}
        .audit-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }}
        .audit-table th, .audit-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }}
        .audit-table th {{
            background: #141f33;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .audit-table tr:hover td {{
            background: var(--bg-card-hover);
        }}
        footer {{
            text-align: center;
            padding-top: 32px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-icon">[+]</div>
                <div>
                    <h1>WinMedic Diagnostic Report</h1>
                    <div class="meta-text">System: <strong>{hostname}</strong> │ Generated: {timestamp}</div>
                </div>
            </div>
            <div class="health-badge-container">
                <div>
                    <div class="stat-label">Health Score</div>
                    <div class="meta-text">System health</div>
                </div>
                <div class="health-score">{health_score}<span style="font-size: 18px; font-weight: 500; color: var(--text-muted);">/100</span></div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Gesamte Befunde</div>
                <div class="stat-val val-cyan">{total_issues}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical faults</div>
                <div class="stat-val val-crit">{crit_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Warnings</div>
                <div class="stat-val val-warn">{warn_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Fixed / open</div>
                <div class="stat-val"><span class="val-fixed">{fixed_count}</span> <span style="font-size: 16px; color: var(--text-muted);">/ {open_count}</span></div>
            </div>
        </div>

        <section class="section">
            <h2 class="section-heading">Diagnostic Findings &amp; Analysis</h2>
            {issues_html}
        </section>

        {audit_html}

        <footer>
            Generated with <strong>WinMedic v{version}</strong> – Advanced Windows Self-Healing &amp; Diagnostics
        </footer>
    </div>
</body>
</html>
"#,
            hostname = escape_html(&hostname),
            timestamp = timestamp,
            health_color = health_color,
            health_score = health_score,
            total_issues = issues.len(),
            crit_count = crit_count,
            warn_count = warn_count,
            fixed_count = fixed_count,
            open_count = open_count,
            issues_html = issues_html,
            audit_html = audit_html,
            version = env!("CARGO_PKG_VERSION"),
        )
    }

    /// Save report to `path` detecting format by extension (`.html`, `.md`, `.json`).
    pub fn save_report(
        path: &Path,
        issues: &[Issue],
        health_score: u8,
        audit_entries: &[AuditEntry],
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("html")
            .to_lowercase();

        let content = match extension.as_str() {
            "json" => Self::to_json(issues, health_score, audit_entries),
            "md" | "markdown" => Self::to_markdown(issues, health_score, audit_entries),
            _ => Self::to_html(issues, health_score, audit_entries),
        };

        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::RiskScore;

    fn sample_issues() -> Vec<Issue> {
        vec![
            Issue::new(
                "sys_sfc_corrupt",
                "system_integrity",
                "Corrupted system files found",
                "System integrity",
                Severity::Critical,
                RiskScore::Low,
                "SFC reported corrupted files.",
                "Errors found in CBS.log",
                "Run a DISM and SFC repair",
                vec!["DISM /Online /Cleanup-Image /RestoreHealth".to_string()],
            ),
            Issue::new(
                "storage_temp_bloat",
                "storage",
                "Temp files are using a lot of space",
                "Storage & Cleanup",
                Severity::Warning,
                RiskScore::Low,
                "1500 MB of temp files found.",
                "C:\\Windows\\Temp",
                "Clean up temp files safely",
                vec!["Clean up".to_string()],
            ),
        ]
    }

    #[test]
    fn test_to_json_validity() {
        let issues = sample_issues();
        let json = DiagnosticReporter::to_json(&issues, 75, &[]);
        assert!(json.contains("sys_sfc_corrupt"));
        assert!(json.contains("\"health_score\": 75"));
    }

    #[test]
    fn test_to_markdown_contains_sections() {
        let issues = sample_issues();
        let md = DiagnosticReporter::to_markdown(&issues, 65, &[]);
        assert!(md.contains("# WinMedic Diagnostic & System Report"));
        assert!(md.contains("Corrupted system files found"));
        assert!(md.contains("65/100"));
    }

    #[test]
    fn test_to_html_contains_structure() {
        let issues = sample_issues();
        let html = DiagnosticReporter::to_html(&issues, 80, &[]);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("WinMedic Diagnostic Report"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("Corrupted system files found"));
    }

    #[test]
    fn test_save_report_formats() {
        let temp_dir = std::env::temp_dir().join("winmedic_test_reports");
        let issues = sample_issues();

        let html_path = temp_dir.join("report.html");
        assert!(DiagnosticReporter::save_report(&html_path, &issues, 80, &[]).is_ok());
        assert!(
            std::fs::read_to_string(&html_path)
                .unwrap()
                .contains("<!DOCTYPE html>")
        );

        let md_path = temp_dir.join("report.md");
        assert!(DiagnosticReporter::save_report(&md_path, &issues, 80, &[]).is_ok());
        assert!(
            std::fs::read_to_string(&md_path)
                .unwrap()
                .contains("# WinMedic")
        );

        let json_path = temp_dir.join("report.json");
        assert!(DiagnosticReporter::save_report(&json_path, &issues, 80, &[]).is_ok());
        assert!(
            std::fs::read_to_string(&json_path)
                .unwrap()
                .contains("\"health_score\": 80")
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
