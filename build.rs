#[cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("ProductName", "WinMedic");
    res.set(
        "FileDescription",
        "WinMedic – Windows Self-Healing & Diagnostic TUI",
    );
    res.set("CompanyName", "SecretLUL");
    res.set("LegalCopyright", "Copyright (c) 2026 SecretLUL");
    res.compile().expect("Failed to compile Windows PE resources");
}

#[cfg(not(windows))]
fn main() {}
