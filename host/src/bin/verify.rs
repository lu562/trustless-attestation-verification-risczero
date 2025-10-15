use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use borsh::BorshDeserialize;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

use tavern::server::Risc0Proof;

#[derive(Parser, Debug)]
#[command(name = "verify", about = "Verify a RISC Zero proof locally", version)]
struct Args {
    /// Path to the proof file (JSON format with a "proof" field containing base64-encoded data)
    #[arg(short, long)]
    proof_path: PathBuf,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let proof_content = fs::read_to_string(&args.proof_path)?;
    let json: serde_json::Value = serde_json::from_str(&proof_content)?;

    // Extract the base64-encoded proof
    let proof_b64 = if let Some(proof_obj) = json.get("proof") {
        if let Some(proof_str) = proof_obj.get("proof").and_then(|p| p.as_str()) {
            proof_str
        } else if let Some(proof_str) = proof_obj.as_str() {
            proof_str
        } else {
            return Err(anyhow::anyhow!("Invalid proof format: 'proof' field must be a string or an object with a 'proof' field"));
        }
    } else {
        return Err(anyhow::anyhow!(
            "Invalid JSON format: missing 'proof' field"
        ));
    };

    // Decode the base64 proof
    let proof_bytes = general_purpose::STANDARD.decode(proof_b64)?;

    // Deserialize the proof
    let proof = borsh::from_slice::<Risc0Proof>(&proof_bytes)?;

    // Verify the proof
    match proof.receipt.verify(proof.image_id) {
        Ok(_) => {
            if args.format == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "message": "Proof verification successful"
                    })
                );
            } else {
                println!("Proof verification successful");
            }
            Ok(())
        }
        Err(e) => {
            if args.format == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": false,
                        "message": format!("Proof verification failed: {}", e)
                    })
                );
            } else {
                eprintln!("Proof verification failed: {}", e);
            }
            Err(anyhow::anyhow!("Verification failed: {}", e))
        }
    }
}
