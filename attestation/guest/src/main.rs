use sev::certs::snp::{Certificate, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use risc0_zkvm::guest::env;
use std::io::Read;

mod utils;
use utils::{SnpOid, check_cert_bytes, snp_verify_attestation_tcb};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (parsed_report, pem_data): (AttestationReport, Vec<u8>) = env::read();

    println!("Parsed SEV-SNP Report: {}", parsed_report);

    let vcek_certificate = Certificate::from_pem(&pem_data)?; //fix
    match (&vcek_certificate, &parsed_report).verify() {
        Ok(()) => {
            println!("Verification of Attestation report signature successful!");
        }
        Err(e) => {
            println!("Verification failed: {}", e);
            std::process::exit(1);
        }
    }
    match snp_verify_attestation_tcb(vcek_certificate, parsed_report, false) {
        Ok(()) => {
            println!("TCB verification successful!");
        }
        Err(e) => {
            println!("TCB verification failed: {}", e);
            std::process::exit(1);
        }
    }
    env::commit(&parsed_report.report_data.to_vec());
    Ok(())
}
