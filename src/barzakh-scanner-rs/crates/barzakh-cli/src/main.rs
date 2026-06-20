use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use barzakh_core::{BarzakhScanner, Baseline, ReportFormat};

#[derive(Parser, Debug)]
#[command(name = "barzakh-scanner")]
#[command(about = "UEFI Bootkit Detection Engine")]
#[command(version)]
struct Cli {
    /// Path to firmware image or memory dump to scan
    #[arg(short, long)]
    target: PathBuf,

    /// Path to baseline configuration JSON
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Generate report after scan
    #[arg(short, long)]
    report: bool,

    /// Output path for report
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Report format (html, json, markdown)
    #[arg(short, long, default_value = "json")]
    format: String,

    /// Specific detector types to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    scan_types: Option<Vec<String>>,

    /// Validate scanner against a corpus directory
    #[arg(long)]
    validate: bool,

    /// Path to validation corpus
    #[arg(long)]
    corpus: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let baseline = if let Some(ref path) = cli.baseline {
        Some(Baseline::load(path)?)
    } else {
        None
    };

    let mut scanner = BarzakhScanner::new(baseline);

    if cli.validate {
        if let Some(ref corpus_path) = cli.corpus {
            let metrics = scanner.validate_against_corpus(corpus_path)?;
            println!("Validation Results:");
            println!("  True Positives:  {}", metrics.true_positives);
            println!("  False Positives: {}", metrics.false_positives);
            println!("  True Negatives:  {}", metrics.true_negatives);
            println!("  False Negatives: {}", metrics.false_negatives);
            println!("  TPR: {:.4}", metrics.true_positive_rate);
            println!("  FPR: {:.4}", metrics.false_positive_rate);
            return Ok(());
        } else {
            anyhow::bail!("--corpus path required for validation mode");
        }
    }

    let scan_types: Option<Vec<String>> = cli.scan_types;
    let scan_types_refs: Option<Vec<&str>> = scan_types
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let result = scanner.scan(&cli.target, scan_types_refs.as_deref());

    println!("Scan complete: {} findings", result.summary.total_findings);
    println!(
        "  Critical: {} | High: {} | Medium: {} | Low: {}",
        result.summary.critical_count,
        result.summary.high_count,
        result.summary.medium_count,
        result.summary.low_count,
    );
    println!(
        "  Bootkit detected: {}",
        if result.summary.bootkit_detected {
            "YES"
        } else {
            "no"
        }
    );
    println!("  Duration: {:.3}s", result.scan_info.duration_seconds);

    if cli.report {
        let format = ReportFormat::from_str(&cli.format)
            .ok_or_else(|| anyhow::anyhow!("Unknown format: {}", cli.format))?;
        let output = cli.output.unwrap_or_else(|| {
            let ext = match format {
                ReportFormat::Html => "html",
                ReportFormat::Json => "json",
                ReportFormat::Markdown => "md",
            };
            PathBuf::from(format!("report.{}", ext))
        });
        scanner.generate_report(&output, format)?;
        println!("Report written to: {}", output.display());
    }

    Ok(())
}
