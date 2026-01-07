use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "prepare-input",
    about = "Write a JSON containing Base64-encoded report.bin and vcek.pem",
    version
)]
struct Args {
    /// Path to SEV-SNP attestation report in raw binary
    #[arg(short, long, value_name = "INPUT-REPORT-PATH", required = true)]
    report: PathBuf,

    /// Path to VCEK certificate in PEM format
    #[arg(short, long, value_name = "INPUT-VCEK-PATH", required = true)]
    vcek: PathBuf,

    /// Output JSON path
    #[arg(short, long, value_name = "OUTPUT-JSON-PATH", required = true)]
    out: PathBuf,
}

#[derive(Serialize)]
struct Output {
    /// Base64URL encoded report.bin
    report: String,
    /// Base64URL encoded vcek.pem
    vcek: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let report_bytes = fs::read(&args.report)
        .with_context(|| format!("Failed to read report file: {}", args.report.display()))?;
    let vcek_bytes = fs::read(&args.vcek)
        .with_context(|| format!("Failed to read vcek file: {}", args.vcek.display()))?;

    let out = Output {
        report: STANDARD.encode(report_bytes),
        vcek: STANDARD.encode(vcek_bytes),
    };

    let json = serde_json::to_string(&out)?;
    fs::write(&args.out, json)
        .with_context(|| format!("Failed to write output file: {}", args.out.display()))?;

    Ok(())
}
