//! The executable Windows is asked to start, rather than the code behind it.

/// Windows raises UAC before WinMedic starts only because the manifest in the
/// executable demands Administrator rights, and nothing inside WinMedic offers
/// to elevate any more. Read from the built binary, as MSVC's linker wrote it.
#[test]
#[cfg(target_env = "msvc")]
fn the_executable_demands_administrator_rights() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_winmedic"))
        .expect("cargo builds the binary before its integration tests");
    let text = String::from_utf8_lossy(&exe);
    assert!(
        text.contains("<requestedExecutionLevel level='requireAdministrator' />"),
        "winmedic.exe carries no requireAdministrator manifest"
    );
}
