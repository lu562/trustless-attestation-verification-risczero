use attestation::SEV_ATTESTATION_ID;
use borsh::from_slice;
use risc0_zkvm::{guest::env, Receipt};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut raw_bytes).unwrap();
    let receipts: Vec<Receipt> = from_slice(&raw_bytes).expect("Failed to deserialize receipts");
    println!("{:?}", receipts);
    for receipt in receipts {
        receipt.verify(SEV_ATTESTATION_ID)?;
    }
    env::commit(&true);
    Ok(())
}
