fn main() {
    // Embed the PELens icon and version metadata into the Windows executable.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/pelens.ico")
            .set("ProductName", "PELens")
            .set("FileDescription", "PELens CLI - PE malware initial assessment")
            .set("LegalCopyright", "PELens contributors");
        if let Err(e) = res.compile() {
            println!("cargo:warning=icon not embedded: {e}");
        }
    }
    println!("cargo:rerun-if-changed=../../assets/pelens.ico");
}
