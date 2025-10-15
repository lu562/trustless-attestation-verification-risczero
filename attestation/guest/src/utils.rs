// The code in this file is copied from snpguest (https://github.com/virtee/snpguest/blob/main/src/verify.rs)
use anyhow::Context;
use anyhow::Result;
use asn1_rs::{FromDer, oid, Oid};
use x509_parser::{certificate::X509Certificate, prelude::X509Extension};

use sev::certs::snp::{Certificate, Verifiable};
use sev::firmware::guest::AttestationReport;

pub enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

impl SnpOid {
    pub fn oid(&self) -> Oid<'static> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
            SnpOid::Fmc => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9),
        }
    }
}

pub fn snp_verify_attestation_tcb(
    vcek: Certificate,
    att_report: AttestationReport,
    quiet: bool,
) -> Result<()> {
    let vek_der = vcek.to_der().context("Could not convert VEK to der.")?;
    let (_, vek_x509) =
        X509Certificate::from_der(&vek_der).context("Could not create X509Certificate from der")?;
    // Collect extensions from VEK
    let extensions: std::collections::HashMap<Oid, &X509Extension> = vek_x509
        .extensions_map()
        .context("Failed getting VEK oids.")?;

    // Compare bootloaders
    if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
        if !check_cert_bytes(cert_bl, &att_report.reported_tcb.bootloader.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB Boot Loader and Certificate Boot Loader mismatch encountered."
            ));
        }
        if !quiet {
            println!("Reported TCB Boot Loader from certificate matches the attestation report.");
        }
    }

    // Compare TEE information
    if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
        if !check_cert_bytes(cert_tee, &att_report.reported_tcb.tee.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB TEE and Certificate TEE mismatch encountered."
            ));
        }
        if !quiet {
            println!("Reported TCB TEE from certificate matches the attestation report.");
        }
    }

    // Compare SNP information
    if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
        if !check_cert_bytes(cert_snp, &att_report.reported_tcb.snp.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB SNP and Certificate SNP mismatch encountered."
            ));
        }
        if !quiet {
            println!("Reported TCB SNP from certificate matches the attestation report.");
        }
    }

    // Compare Microcode information
    if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
        if !check_cert_bytes(cert_ucode, &att_report.reported_tcb.microcode.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB Microcode and Certificate Microcode mismatch encountered."
            ));
        }
        if !quiet {
            println!("Reported TCB Microcode from certificate matches the attestation report.");
        }
    }

    // Compare HWID information only on VCEK
    if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
        if !check_cert_bytes(cert_hwid, &att_report.chip_id) {
            return Err(anyhow::anyhow!(
                "Report TCB ID and Certificate ID mismatch encountered."
            ));
        }
        if !quiet {
            println!("Chip ID from certificate matches the attestation report.");
        }
    }

    Ok(())
}

/// Check the cert extension byte to value
pub fn check_cert_bytes(ext: &x509_parser::prelude::X509Extension, val: &[u8]) -> bool {
    match ext.value[0] {
        // Integer
        0x2 => {
            if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
                panic!("check_cert_bytes: Invalid integer encountered!");
            } else if let Some(byte_value) = ext.value.last() {
                return byte_value == &val[0];
            } else {
                return false;
            }
        }
        // Octet String
        0x4 => {
            if ext.value[1] != 0x40 {
                panic!("check_cert_bytes: Invalid octet length encountered!");
            }
            if ext.value[2..].len() != 0x40 {
                panic!("check_cert_bytes: Invalid number of bytes encountered!");
            }
            if val.len() != 0x40 {
                panic!("check_cert_bytes: Invalid certificate harward id length encountered!");
            }

            return &ext.value[2..] == val;
        }
        // Legacy and others.
        _ => {
            // Old VCEK without x509 DER encoding, might be deprecated in the future.
            if ext.value.len() == 0x40 && val.len() == 0x40 {
                return ext.value == val;
            }
        }
    }
    panic!("check_cert_bytes: Invalid type encountered!");
}