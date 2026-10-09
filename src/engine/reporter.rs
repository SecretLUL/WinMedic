use crate::engine::issue::{Issue, Severity};
use crate::safety::audit::AuditEntry;
use colored::*;
use std::path::Path;

pub struct DiagnosticReporter;

/// The app icon's source, drawn in the HTML report's header.
const LOGO_SVG: &str = include_str!("../../assets/logo.svg");

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The ASCII punctuation that CommonMark or GFM gives a meaning somewhere in a
/// line: escapes, code spans, emphasis, links and images, raw HTML, entities,
/// table cells, strikethrough, and the markers that open a block at the start
/// of a line (headings, lists, quotes, rules, fences, setext underlines). `$`
/// is here too, because GitHub reads a pair of them as math.
const MD_SPECIAL: &[char] = &[
    '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '<', '>', '&',
    '~', '=', '$',
];

/// The line breaks a value must not carry into a table row, heading or list item.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Escape a value for Markdown text outside a code block: a heading, a list
/// item, a paragraph or a table cell. Every character in `MD_SPECIAL` is
/// backslash-escaped, so the value stays text, and each run of line breaks
/// becomes one space, so the value stays on the line it was written on.
fn escape_md(value: &str) -> String {
    let flat = value
        .split(is_line_break)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut escaped = String::with_capacity(flat.len());
    for c in flat.chars() {
        if MD_SPECIAL.contains(&c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// The line a report adds when the user archived some of the findings.
/// What a report says of a finding, decided as the window decides it: a
/// repair that succeeded but waits for Windows to restart is neither fixed
/// nor open, and the window marks it "Restart".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Fixed,
    Restart,
    Failed,
    Advice,
    Open,
}

impl Status {
    fn of(issue: &Issue) -> Self {
        if issue.is_fixed {
            Self::Fixed
        } else if issue.is_reboot_pending {
            Self::Restart
        } else if issue.fix_error.is_some() {
            Self::Failed
        } else if issue.advice_only {
            Self::Advice
        } else {
            Self::Open
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fixed => "FIXED",
            Self::Restart => "RESTART",
            Self::Failed => "FAILED",
            Self::Advice => "ADVICE",
            Self::Open => "OPEN",
        }
    }
}

/// How many findings are fixed, how many wait for the restart, and how many
/// are open: everything else.
fn status_counts(issues: &[Issue]) -> (usize, usize, usize) {
    let fixed = issues
        .iter()
        .filter(|i| Status::of(i) == Status::Fixed)
        .count();
    let restart = issues
        .iter()
        .filter(|i| Status::of(i) == Status::Restart)
        .count();
    (fixed, restart, issues.len() - fixed - restart)
}

fn archived_note(archived: usize) -> Option<String> {
    match archived {
        0 => None,
        1 => Some("1 archived finding is not included.".to_string()),
        n => Some(format!("{n} archived findings are not included.")),
    }
}

/// A fenced code block holding `content`. The fence is one backtick longer
/// than the longest run inside the content (and never shorter than three), so
/// no line of the content can close the block early.
fn md_code_block(content: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in content.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat((longest + 1).max(3));
    format!("{fence}\n{content}\n{fence}")
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
          Healing Windows at 1 HP. Fast. Reliable. Easy.
"#
            .cyan()
            .bold()
        );
    }

    /// Print issues formatted in CLI console. `archived` findings are left
    /// out, and the report says how many.
    pub fn print_cli_report(issues: &[Issue], health_score: u8, archived: usize) {
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
        println!("Issues found: {}", issues.len());
        if let Some(note) = archived_note(archived) {
            println!("{note}");
        }
        println!();

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
            } else if issue.advice_only {
                "[ADVICE]".white()
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

    /// Export report as Markdown. Every value that does not come from WinMedic
    /// itself is escaped for Markdown text, and the technical details are
    /// fenced, so no value can break a table, a heading or a list, or put
    /// markup into the page. The labels, counts and dates WinMedic writes stay
    /// readable as they are.
    pub fn to_markdown(
        issues: &[Issue],
        health_score: u8,
        audit_entries: &[AuditEntry],
        archived: usize,
    ) -> String {
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
        let (fixed_count, restart_count, open_count) = status_counts(issues);
        let waiting = if restart_count > 0 {
            format!(", {restart_count} waiting for a restart")
        } else {
            String::new()
        };

        let mut md = format!(
            "# WinMedic Diagnostic & System Report\n\n\
            - **System:** {}\n\
            - **Generated:** {}\n\
            - **Health score:** {}/100\n\
            - **Issues found:** {} (critical: {}, warnings: {}, informational: {})\n\
            - **Status:** {} fixed{}, {} open\n\n",
            escape_md(&hostname),
            timestamp,
            health_score,
            issues.len(),
            crit_count,
            warn_count,
            info_count,
            fixed_count,
            waiting,
            open_count
        );
        if let Some(note) = archived_note(archived) {
            md.push_str(&format!("{note}\n\n"));
        }
        md.push_str("---\n\n## Findings\n\n");

        if issues.is_empty() {
            md.push_str("**No issues found.** The system is in excellent shape.\n\n");
        } else {
            for (idx, issue) in issues.iter().enumerate() {
                // The same three strings the GUI once carried a copy of.
                let sev_str = issue.severity.badge();
                let status_str = format!("[{}]", Status::of(issue).label());

                md.push_str(&format!(
                    "### {}. {} [{}] {}\n\n\
                    - **Category:** {}\n\
                    - **Module:** {}\n\
                    - **Risk level:** {}\n\
                    - **Status:** {}\n\
                    - **Description:** {}\n\n\
                    **Technical details:**\n{}\n\n\
                    **Recommended fix:** {}\n\n",
                    idx + 1,
                    sev_str,
                    status_str,
                    escape_md(&issue.title),
                    escape_md(&issue.category),
                    escape_md(&issue.module_id),
                    issue.risk_score.badge(),
                    status_str,
                    escape_md(&issue.description),
                    md_code_block(&issue.technical_details),
                    escape_md(&issue.recommended_fix)
                ));

                if let Some(ref err) = issue.fix_error {
                    md.push_str(&format!("> **Repair error:** {}\n\n", escape_md(err)));
                }

                if !issue.fix_steps.is_empty() {
                    md.push_str("**Planned steps:**\n");
                    for (s_idx, step) in issue.fix_steps.iter().enumerate() {
                        md.push_str(&format!("{}. {}\n", s_idx + 1, escape_md(step)));
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
                    escape_md(&entry.timestamp),
                    escape_md(&entry.action_type),
                    escape_md(&entry.module_id),
                    escape_md(&entry.title),
                    escape_md(&entry.status),
                    escape_md(&entry.details)
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
    pub fn to_html(
        issues: &[Issue],
        health_score: u8,
        audit_entries: &[AuditEntry],
        archived: usize,
    ) -> String {
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
        let (fixed_count, restart_count, open_count) = status_counts(issues);
        // A third number only when a repair waits for the restart, so a
        // report of a scan reads as it always did.
        let (counts_label, waiting) = if restart_count > 0 {
            (
                "Fixed / restart / open",
                format!("<span class=\"val-warn\">{restart_count}</span> / "),
            )
        } else {
            ("Fixed / open", String::new())
        };

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

                let status = Status::of(issue);
                let status_class = match status {
                    Status::Fixed => "status-fixed",
                    Status::Restart => "status-restart",
                    Status::Failed => "status-failed",
                    Status::Advice | Status::Open => "status-open",
                };
                let status_label = status.label();

                let mut steps_html = String::new();
                if !issue.fix_steps.is_empty() {
                    steps_html.push_str(if issue.advice_only {
                        "<div class=\"steps-title\">What to do:</div><ol class=\"steps-list\">"
                    } else {
                        "<div class=\"steps-title\">Planned steps:</div><ol class=\"steps-list\">"
                    });
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
        .logo-icon svg {{
            display: block;
            width: 44px;
            height: 44px;
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
        .status-restart {{ background: rgba(245, 158, 11, 0.2); color: var(--amber); }}
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
                <div class="logo-icon">{logo}</div>
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
                <div class="stat-label">Findings</div>
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
                <div class="stat-label">{counts_label}</div>
                <div class="stat-val"><span class="val-fixed">{fixed_count}</span> <span style="font-size: 16px; color: var(--text-muted);">/ {waiting}{open_count}</span></div>
            </div>
        </div>

        <section class="section">
            <h2 class="section-heading">Diagnostic Findings &amp; Analysis</h2>
            {archived_html}
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
            logo = LOGO_SVG,
            hostname = escape_html(&hostname),
            timestamp = timestamp,
            health_color = health_color,
            health_score = health_score,
            total_issues = issues.len(),
            crit_count = crit_count,
            warn_count = warn_count,
            counts_label = counts_label,
            fixed_count = fixed_count,
            waiting = waiting,
            open_count = open_count,
            archived_html = archived_note(archived)
                .map(|note| format!("<p class=\"meta-text\">{note}</p>"))
                .unwrap_or_default(),
            issues_html = issues_html,
            audit_html = audit_html,
            version = env!("CARGO_PKG_VERSION"),
        )
    }

    /// The audit entries logged at or after `since` (`%Y-%m-%d %H:%M:%S`, the
    /// audit log's own format): what a report's own scan and repairs did.
    ///
    /// Handed the whole history, every report carried every scan and repair
    /// ever logged on the PC (16,767 entries and 3.4 MB on the development
    /// machine) - a record of the machine nobody meant to pass on with it.
    pub fn audit_since(entries: &[AuditEntry], since: &str) -> Vec<AuditEntry> {
        entries
            .iter()
            .filter(|entry| entry.timestamp.as_str() >= since)
            .cloned()
            .collect()
    }

    /// Save report to `path` detecting format by extension (`.html`, `.md`, `.json`).
    /// The HTML and Markdown reports say how many `archived` findings they
    /// leave out; the JSON report is for scripts and stays as it was.
    pub fn save_report(
        path: &Path,
        issues: &[Issue],
        health_score: u8,
        audit_entries: &[AuditEntry],
        archived: usize,
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
            "md" | "markdown" => Self::to_markdown(issues, health_score, audit_entries, archived),
            _ => Self::to_html(issues, health_score, audit_entries, archived),
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
        let md = DiagnosticReporter::to_markdown(&issues, 65, &[], 0);
        assert!(md.contains("# WinMedic Diagnostic & System Report"));
        assert!(md.contains("Corrupted system files found"));
        assert!(md.contains("65/100"));
    }

    #[test]
    fn test_to_html_contains_structure() {
        let issues = sample_issues();
        let html = DiagnosticReporter::to_html(&issues, 80, &[], 0);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("WinMedic Diagnostic Report"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("Corrupted system files found"));
        assert!(!html.contains("Gesamte"), "a German label in the report");
    }

    /// The header carries the app icon itself, not a text stand-in for it.
    #[test]
    fn the_html_report_header_draws_the_logo() {
        let html = DiagnosticReporter::to_html(&sample_issues(), 80, &[], 0);
        let header = &html[html.find("<header>").unwrap()..html.find("</header>").unwrap()];
        assert!(header.contains("<svg"), "no logo in the header");
        assert!(header.contains(r#"viewBox="0 0 256 256""#));
        assert!(!header.contains("[+]"));
    }

    /// Archived findings are left out, and the report says how many; the
    /// JSON report stays as scripts know it.
    #[test]
    fn a_report_says_how_many_archived_findings_it_leaves_out() {
        let issues = sample_issues();
        let md = DiagnosticReporter::to_markdown(&issues, 80, &[], 2);
        assert!(
            md.contains("\n2 archived findings are not included.\n"),
            "{md}"
        );
        let html = DiagnosticReporter::to_html(&issues, 80, &[], 1);
        assert!(html.contains(">1 archived finding is not included.<"));

        for report in [
            DiagnosticReporter::to_markdown(&issues, 80, &[], 0),
            DiagnosticReporter::to_html(&issues, 80, &[], 0),
        ] {
            assert!(!report.contains("archived finding"));
        }
    }

    /// A finding as `run_repairs` leaves it after a repair that succeeded and
    /// needs Windows to restart: not fixed yet, unticked, no error.
    fn waiting_for_restart() -> Issue {
        let mut issue = sample_issues().remove(0);
        issue.requires_reboot = true;
        issue.is_reboot_pending = true;
        issue.is_selected = false;
        issue
    }

    #[test]
    fn a_repair_waiting_for_the_restart_is_not_open_in_the_markdown_report() {
        let issues = vec![waiting_for_restart(), sample_issues().remove(1)];
        let md = DiagnosticReporter::to_markdown(&issues, 80, &[], 0);
        assert!(
            md.contains("### 1. [!] CRITICAL [[RESTART]] Corrupted system files found"),
            "{md}"
        );
        assert!(md.contains("- **Status:** [RESTART]\n"));
        assert!(md.contains("### 2. [!] WARNING [[OPEN]] Temp files"));
        assert!(md.contains("- **Status:** 0 fixed, 1 waiting for a restart, 1 open\n"));
    }

    #[test]
    fn a_repair_waiting_for_the_restart_is_not_open_in_the_html_report() {
        let mut fixed = sample_issues().remove(1);
        fixed.is_fixed = true;
        let html = DiagnosticReporter::to_html(&[waiting_for_restart(), fixed], 80, &[], 0);
        assert!(html.contains(r#"<span class="status-pill status-restart">RESTART</span>"#));
        assert!(html.contains(r#"<span class="status-pill status-fixed">FIXED</span>"#));
        assert!(!html.contains(">OPEN</span>"));
        assert!(html.contains(">Fixed / restart / open<"));
        assert!(html.contains(r#"<span class="val-warn">1</span> / 0</span>"#));
    }

    /// Without a repair waiting for the restart, the counts read as before.
    #[test]
    fn a_report_without_a_waiting_repair_counts_fixed_and_open() {
        let md = DiagnosticReporter::to_markdown(&sample_issues(), 80, &[], 0);
        assert!(md.contains("- **Status:** 0 fixed, 2 open\n"));
        let html = DiagnosticReporter::to_html(&sample_issues(), 80, &[], 0);
        assert!(html.contains(">Fixed / open<"));
        assert!(!html.contains("status-pill status-restart"));
        assert!(!html.contains("val-warn\">"));
    }

    #[test]
    fn test_save_report_formats() {
        let temp_dir = std::env::temp_dir().join("winmedic_test_reports");
        let issues = sample_issues();

        let html_path = temp_dir.join("report.html");
        assert!(DiagnosticReporter::save_report(&html_path, &issues, 80, &[], 0).is_ok());
        assert!(
            std::fs::read_to_string(&html_path)
                .unwrap()
                .contains("<!DOCTYPE html>")
        );

        let md_path = temp_dir.join("report.md");
        assert!(DiagnosticReporter::save_report(&md_path, &issues, 80, &[], 0).is_ok());
        assert!(
            std::fs::read_to_string(&md_path)
                .unwrap()
                .contains("# WinMedic")
        );

        let json_path = temp_dir.join("report.json");
        assert!(DiagnosticReporter::save_report(&json_path, &issues, 80, &[], 0).is_ok());
        assert!(
            std::fs::read_to_string(&json_path)
                .unwrap()
                .contains("\"health_score\": 80")
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn a_report_carries_only_the_entries_of_its_own_run() {
        let entry = |timestamp: &str| AuditEntry {
            timestamp: timestamp.to_string(),
            action_type: "SCAN".to_string(),
            module_id: "engine".to_string(),
            title: "Scan".to_string(),
            status: "SUCCESS".to_string(),
            details: String::new(),
        };
        let history = [
            entry("2026-09-24 10:00:00"),
            entry("2026-09-26 11:59:59"),
            entry("2026-09-26 12:00:00"),
            entry("2026-09-26 12:03:10"),
        ];
        let run = DiagnosticReporter::audit_since(&history, "2026-09-26 12:00:00");
        assert_eq!(run, history[2..]);
    }

    /// One finding with the given title and technical details; the rest is fixed.
    fn finding(title: &str, technical_details: &str) -> Issue {
        Issue::new(
            "test_finding",
            "test_module",
            title,
            "Test category",
            Severity::Warning,
            RiskScore::Low,
            "A description.",
            technical_details,
            "A fix.",
            vec!["A step.".to_string()],
        )
    }

    fn audit_entry(title: &str, details: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-09-26 12:00:00".to_string(),
            action_type: "FIX".to_string(),
            module_id: "test_module".to_string(),
            title: title.to_string(),
            status: "FAILED".to_string(),
            details: details.to_string(),
        }
    }

    /// Splits `md` into the text outside its fenced code blocks and the blocks
    /// as (fence length, body). A block opens on a line of backticks and closes
    /// on the next line that is at least as long and holds nothing else, the
    /// way CommonMark reads a backtick fence.
    fn outside_and_blocks(md: &str) -> (String, Vec<(usize, String)>) {
        let mut outside = String::new();
        let mut blocks = Vec::new();
        let mut open: Option<(usize, Vec<&str>)> = None;
        for line in md.lines() {
            let only_backticks = !line.is_empty() && line.bytes().all(|b| b == b'`');
            match open.take() {
                Some((fence, body)) if only_backticks && line.len() >= fence => {
                    blocks.push((fence, body.join("\n")));
                }
                Some((fence, mut body)) => {
                    body.push(line);
                    open = Some((fence, body));
                }
                None if only_backticks && line.len() >= 3 => {
                    open = Some((line.len(), Vec::new()));
                }
                None => {
                    outside.push_str(line);
                    outside.push('\n');
                }
            }
        }
        assert!(open.is_none(), "a fenced code block is never closed");
        (outside, blocks)
    }

    /// How many `target` characters in `line` are not backslash-escaped.
    fn unescaped_count(line: &str, target: char) -> usize {
        let mut count = 0;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                chars.next();
            } else if c == target {
                count += 1;
            }
        }
        count
    }

    /// Every table row outside the code blocks keeps the audit table's six
    /// columns: seven pipes that are not escaped.
    fn assert_table_rows_keep_their_columns(outside: &str) {
        for row in outside.lines().filter(|line| line.starts_with('|')) {
            assert_eq!(
                unescaped_count(row, '|'),
                7,
                "a table row changed its columns: {row}"
            );
        }
    }

    #[test]
    fn escape_md_escapes_markup_and_flattens_line_breaks() {
        assert_eq!(
            escape_md(r"a|b<c>&d*e_f`g[h](i)#j+k-l.m!n~o\p=q$r"),
            r"a\|b\<c\>\&d\*e\_f\`g\[h\]\(i\)\#j\+k\-l\.m\!n\~o\\p\=q\$r"
        );
        assert_eq!(escape_md("one\r\ntwo\n\n\u{2028}three"), "one two three");
        assert_eq!(escape_md("Plain text, 1 of 2"), "Plain text, 1 of 2");
    }

    #[test]
    fn md_code_block_fences_are_longer_than_any_backtick_run() {
        assert_eq!(md_code_block("plain"), "```\nplain\n```");
        assert_eq!(md_code_block("a ``` b"), "````\na ``` b\n````");
        assert_eq!(md_code_block("a ```` b ``"), "`````\na ```` b ``\n`````");
    }

    #[test]
    fn a_pipe_in_a_title_or_a_cell_does_not_add_a_column() {
        let md = DiagnosticReporter::to_markdown(
            &[finding("Cache | stale", "details")],
            60,
            &[audit_entry("Repair | retry", "two | cells")],
            0,
        );
        let (outside, _) = outside_and_blocks(&md);
        assert_eq!(outside.lines().filter(|l| l.starts_with('|')).count(), 3);
        assert_table_rows_keep_their_columns(&outside);
        assert!(md.contains(r"### 1. [!] WARNING [[OPEN]] Cache \| stale"));
        assert!(md.contains(r"| Repair \| retry | FAILED | two \| cells |"));
    }

    #[test]
    fn a_fence_longer_than_any_backtick_run_in_the_details_holds_them() {
        let details = "before\n```\nmiddle\n````\nafter";
        let md = DiagnosticReporter::to_markdown(&[finding("Title", details)], 60, &[], 0);
        let (outside, blocks) = outside_and_blocks(&md);
        assert_eq!(blocks, vec![(5, details.to_string())]);
        assert!(outside.contains(r"**Recommended fix:** A fix\."));
    }

    #[test]
    fn a_tag_in_a_name_is_shown_as_text_not_markup() {
        let tag = "<img src=x onerror=alert(1)>";
        let md = DiagnosticReporter::to_markdown(
            &[finding(tag, "details")],
            60,
            &[audit_entry(tag, "details")],
            0,
        );
        let (outside, _) = outside_and_blocks(&md);
        for line in outside.lines() {
            assert_eq!(
                unescaped_count(line, '<'),
                0,
                "a raw `<img` survives outside a code block: {line}"
            );
        }
        assert!(outside.contains(r"\<img src\=x onerror\=alert\(1\)\>"));
        assert_table_rows_keep_their_columns(&outside);
    }

    #[test]
    fn a_line_break_in_a_value_stays_on_its_line() {
        let mut issue = finding("Title", "details");
        issue.description = "first\n# not a heading\n| not a cell |".to_string();
        let md =
            DiagnosticReporter::to_markdown(&[issue], 60, &[audit_entry("Title", "one\r\ntwo")], 0);
        let (outside, _) = outside_and_blocks(&md);
        assert!(
            outside.contains("- **Description:** first \\# not a heading \\| not a cell \\|\n")
        );
        assert!(!outside.lines().any(|line| line.starts_with("# not")));
        assert!(outside.contains("| one two |"));
        assert_table_rows_keep_their_columns(&outside);
    }
}
