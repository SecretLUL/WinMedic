use crate::engine::issue::{Issue, Severity};
use colored::*;

pub struct DiagnosticReporter;

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
        println!("\n{}", "═══ WINMEDIC DIAGNOSE-BERICHT ═══".cyan().bold());
        println!(
            "Gesamt-Health-Score: {}/100",
            if health_score >= 80 {
                format!("{}", health_score).green().bold()
            } else if health_score >= 50 {
                format!("{}", health_score).yellow().bold()
            } else {
                format!("{}", health_score).red().bold()
            }
        );
        println!("Gefundene Probleme: {}\n", issues.len());

        if issues.is_empty() {
            println!(
                "{}",
                "✔ Keine Probleme gefunden! Ihr System ist in hervorragendem Zustand."
                    .green()
                    .bold()
            );
            return;
        }

        for (idx, issue) in issues.iter().enumerate() {
            let sev_str = match issue.severity {
                Severity::Critical => "[KRITISCH]".red().bold(),
                Severity::Warning => "[WARNUNG]".yellow().bold(),
                Severity::Info => "[INFO]".cyan(),
            };

            let status_str = if issue.is_fixed {
                "[BEHOBEN]".green().bold()
            } else {
                "[OFFEN]".white()
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
            println!("      Empfohlener Fix: {}", issue.recommended_fix.green());
            println!();
        }
    }

    /// Generate JSON representation
    pub fn to_json(issues: &[Issue], health_score: u8) -> String {
        #[derive(serde::Serialize)]
        struct Report<'a> {
            timestamp: String,
            health_score: u8,
            issues_count: usize,
            issues: &'a [Issue],
        }

        let rep = Report {
            timestamp: chrono::Local::now().to_rfc3339(),
            health_score,
            issues_count: issues.len(),
            issues,
        };

        serde_json::to_string_pretty(&rep).unwrap_or_else(|_| "{}".to_string())
    }
}
