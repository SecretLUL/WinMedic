#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("ProductName", "WinMedic");
    res.set(
        "FileDescription",
        "WinMedic – Windows Self-Healing & Diagnostic TUI",
    );
    res.set("CompanyName", "SecretLUL");
    res.set("LegalCopyright", "Copyright (c) 2026 SecretLUL");
    res.compile().unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let res_path = std::path::Path::new(&out_dir).join("resource.res");
    if res_path.exists() {
        println!("cargo:rustc-link-arg={}", res_path.display());
    }
}

#[cfg(not(windows))]
fn main() {}
