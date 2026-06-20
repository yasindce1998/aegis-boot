use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use serde_json::json;

use crate::baseline::Baseline;
use crate::detector::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Json,
    Markdown,
}

impl ReportFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "html" => Some(Self::Html),
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            _ => None,
        }
    }
}

pub struct ReportGenerator<'a> {
    findings: &'a [Finding],
    #[allow(dead_code)]
    baseline: Option<&'a Baseline>,
}

impl<'a> ReportGenerator<'a> {
    pub fn new(findings: &'a [Finding], baseline: Option<&'a Baseline>) -> Self {
        Self { findings, baseline }
    }

    pub fn generate(&self, output: &Path, format: ReportFormat) -> anyhow::Result<()> {
        match format {
            ReportFormat::Html => self.generate_html(output),
            ReportFormat::Json => self.generate_json(output),
            ReportFormat::Markdown => self.generate_markdown(output),
        }
    }

    fn generate_json(&self, output: &Path) -> anyhow::Result<()> {
        let report = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "summary": {
                "total_findings": self.findings.len(),
                "critical": self.findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high": self.findings.iter().filter(|f| f.severity == Severity::High).count(),
                "medium": self.findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low": self.findings.iter().filter(|f| f.severity == Severity::Low).count(),
            },
            "findings": self.findings,
            "correlated_threats": self.correlate_findings(),
        });

        let content = serde_json::to_string_pretty(&report)?;
        std::fs::write(output, content)?;
        Ok(())
    }

    fn generate_html(&self, output: &Path) -> anyhow::Result<()> {
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        let mut findings_html = String::new();
        for finding in self.findings {
            let severity_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            findings_html.push_str(&format!(
                r#"<div class="finding {cls}"><h3>{title}</h3><p class="severity">{sev}</p><p>{desc}</p></div>"#,
                cls = severity_class,
                title = html_escape(&finding.title),
                sev = finding.severity,
                desc = html_escape(&finding.description),
            ));
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html><head><title>Barzakh Scanner Report</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
.summary {{ margin-bottom: 2em; }}
.finding {{ border: 1px solid #ccc; padding: 1em; margin: 0.5em 0; border-radius: 4px; }}
.finding.critical {{ border-color: #d00; background: #fff0f0; }}
.finding.high {{ border-color: #f60; background: #fff5f0; }}
.finding.medium {{ border-color: #fa0; background: #fffaf0; }}
.finding.low {{ border-color: #0a0; background: #f0fff0; }}
.severity {{ font-weight: bold; text-transform: uppercase; }}
</style></head><body>
<h1>Barzakh Scanner Report</h1>
<div class="summary">
<h2>Summary</h2>
<p>Total findings: {total}</p>
<p>Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}</p>
</div>
<h2>Findings</h2>
{findings}
</body></html>"#,
            total = self.findings.len(),
            critical = critical,
            high = high,
            medium = medium,
            low = low,
            findings = findings_html,
        );

        std::fs::write(output, html)?;
        Ok(())
    }

    fn generate_markdown(&self, output: &Path) -> anyhow::Result<()> {
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        let mut md = String::new();
        md.push_str("# Barzakh Scanner Report\n\n");
        md.push_str(&format!("Generated: {}\n\n", Utc::now().to_rfc3339()));
        md.push_str("## Summary\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("| --- | --- |\n");
        md.push_str(&format!("| Critical | {} |\n", critical));
        md.push_str(&format!("| High | {} |\n", high));
        md.push_str(&format!("| Medium | {} |\n", medium));
        md.push_str(&format!("| Low | {} |\n", low));
        md.push_str(&format!("| **Total** | **{}** |\n\n", self.findings.len()));

        md.push_str("## Findings\n\n");
        for finding in self.findings {
            md.push_str(&format!("### [{}] {}\n\n", finding.severity, finding.title));
            md.push_str(&format!("**Detector:** {}\n\n", finding.detector));
            md.push_str(&format!("{}\n\n", finding.description));
            if let Some(ref rec) = finding.recommendation {
                md.push_str(&format!("**Recommendation:** {}\n\n", rec));
            }
            md.push_str("---\n\n");
        }

        std::fs::write(output, md)?;
        Ok(())
    }

    fn correlate_findings(&self) -> Vec<serde_json::Value> {
        let mut address_groups: HashMap<String, Vec<&Finding>> = HashMap::new();

        for finding in self.findings {
            if let Some(ref details) = finding.details {
                if let Some(addr) = details.get("address").or(details.get("offset")) {
                    let key = addr.to_string();
                    address_groups.entry(key).or_default().push(finding);
                }
            }
        }

        let mut correlations = Vec::new();
        for (address, findings) in &address_groups {
            if findings.len() > 1 {
                let max_severity = findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                correlations.push(json!({
                    "address": address,
                    "finding_count": findings.len(),
                    "max_severity": max_severity,
                    "detectors": findings.iter().map(|f| &f.detector).collect::<Vec<_>>(),
                }));
            }
        }

        correlations
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
