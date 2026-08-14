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
}

#[cfg(not(windows))]
fn main() {}
