use std::process::Command;

/// Check whether the current process has Windows Administrator privileges.
pub fn is_admin() -> bool {
    // Check using standard Windows 'net session' probe or whoami /priv
    let output = Command::new("net").arg("session").output();

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Request UAC elevation by relaunching the current executable with 'runas'
pub fn relaunch_as_admin() -> std::io::Result<()> {
    let current_exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                current_exe.display(),
                args_str
            ),
        ])
        .spawn()?;

    Ok(())
}
