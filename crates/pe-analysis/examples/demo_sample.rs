//! Write the synthetic demo samples (harmless, structure only) used for screenshots:
//! `cargo run -p pe-analysis --example demo_sample -- <dir>`
fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| ".".into()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("demo-suspicious.exe"), pe_analysis::testkit::suspicious_sample()).unwrap();
    std::fs::write(dir.join("demo-dotnet.exe"), pe_analysis::testkit::dotnet_sample()).unwrap();
    println!("written to {}", dir.display());
}
