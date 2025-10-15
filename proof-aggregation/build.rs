fn main() {
    risc0_build::embed_methods_with_options(
        [("sev-attestation-aggregation", Default::default())].into(),
    );
}
