#[cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("ProductName", "WinMedic");
    res.set(
        "FileDescription",
        "WinMedic – Windows Self-Healing & Diagnostic GUI",
    );
    res.set("CompanyName", "SecretLUL");
    res.set("LegalCopyright", "Copyright (c) 2026 SecretLUL");
    res.compile()
        .expect("Failed to compile Windows PE resources");

    // Nearly every check and every repair needs Administrator rights, so
    // Windows asks for them before WinMedic starts. The linker writes the
    // manifest rather than winresource, whose resources reach every target:
    // a test executable demanding elevation would not start under an
    // unelevated `cargo test`.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bin=winmedic=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bin=winmedic=/MANIFESTUAC:level='requireAdministrator'");
        // The DLLs the executable imports are loaded from System32 only
        // (LOAD_LIBRARY_SEARCH_SYSTEM32), not from the folder it was started
        // from, which is often Downloads. `main` sets the same rule for
        // every DLL loaded later.
        println!("cargo:rustc-link-arg-bin=winmedic=/DEPENDENTLOADFLAG:0x800");
    }
}

#[cfg(not(windows))]
fn main() {}
