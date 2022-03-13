use std::env;

const INCLUDES: &[&str; 2] = &["proto", "external/googleapis"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = env::var("PROFILE")?;

    tonic_build::configure()
        .build_server(true)
        .build_client(profile == "debug")
        .compile(&["proto/pki.proto"], INCLUDES)?;

    println!("cargo:rerun-if-changed={}", "proto/pki.proto");

    Ok(())
}
