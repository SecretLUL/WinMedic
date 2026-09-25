//! Windows installation media as the repair source for DISM.
//!
//! `DISM /RestoreHealth` takes the files it puts back from Windows Update.
//! When Windows Update cannot deliver them - broken, blocked, a WSUS server
//! without repair content, no internet - DISM stops with one of
//! [`SOURCE_MISSING`]. The `install.wim` of a Windows ISO holds the files of
//! the build it was made from, and DISM repairs from it when it is named as
//! the source.
//!
//! Only files of the exact version the ISO carries can come from it. A PC with
//! newer updates than the ISO, or damage in component versions later updates
//! replaced, needs Windows Update or a repair install: on the development PC
//! the damage was in 10.0.26100.1591 components, replaced by .9278 ones, and
//! the current 25H2 ISO (26200.8037) held neither.
//!
//! The ISO is looked for where a user puts one: the Downloads folder, or
//! already mounted, or on an inserted USB stick or DVD. Which image in it fits
//! is decided by the edition id and the build, which read the same in every
//! display language.

use crate::utils::cmd::{CmdOutput, ps_single_quoted};
use std::path::{Path, PathBuf};

/// The HRESULTs DISM exits with when it found nowhere to take the files from:
/// the source files could not be found, could not be downloaded, a group
/// policy keeps DISM from downloading them, or the repair content was found
/// nowhere (`CBS_E_REPAIR_CONTENT_MISSING`, "Check the internet connectivity
/// or use the Source option").
///
/// DISM exits with the HRESULT it prints as `Error: 0x800f0915`, and with a
/// plain Windows error number as it prints `Error: 11`.
pub const SOURCE_MISSING: [u32; 4] = [0x800F_081F, 0x800F_0906, 0x800F_0907, 0x800F_0915];

/// Whether a DISM run stopped because it had no source for the files.
pub fn source_missing(out: &CmdOutput) -> bool {
    out.exit_code
        .is_some_and(|code| SOURCE_MISSING.contains(&(code as u32)))
}

/// How many ISOs from the Downloads folder are mounted at most, the newest
/// first. Not every ISO there is a Windows one.
const MAX_ISOS: usize = 3;

/// The ISO files directly in `folder`, the newest first.
pub fn isos_in(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut isos: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("iso"))
        })
        .filter_map(|path| Some((path.metadata().ok()?.modified().ok()?, path)))
        .collect();
    isos.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    isos.into_iter()
        .take(MAX_ISOS)
        .map(|(_, path)| path)
        .collect()
}

fn ps_list(isos: &[String]) -> String {
    let quoted: Vec<String> = isos.iter().map(|iso| ps_single_quoted(iso)).collect();
    format!("@({})", quoted.join(", "))
}

/// Mounts each of `isos` that is not mounted yet and lists every Windows
/// image on every drive, one tab-separated line each:
///
/// - `WINDOWS  <edition id>  <build>  <display version>` of this PC,
/// - `MOUNTED  <iso>` for each ISO this script mounted,
/// - `ISO  <drive letter>  <iso>` for each ISO that is mounted now,
/// - `IMAGE  <index>  <edition id>  <version>  <languages>  <file>`,
/// - `FAILED  <iso or file>  <message>`.
///
/// `Get-WindowsImage` needs elevation, as every repair does.
pub fn find_script(isos: &[PathBuf]) -> String {
    let isos: Vec<String> = isos.iter().map(|p| p.display().to_string()).collect();
    format!(
        r#"$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"WINDOWS`t$($os.EditionID)`t$($os.CurrentBuild)`t$($os.DisplayVersion)"
foreach ($iso in {isos}) {{
    try {{
        $image = Get-DiskImage -ImagePath $iso -ErrorAction Stop
        if (-not $image.Attached) {{
            $image = Mount-DiskImage -ImagePath $iso -StorageType ISO -PassThru -ErrorAction Stop
            "MOUNTED`t$iso"
        }}
        "ISO`t$(($image | Get-Volume).DriveLetter)`t$iso"
    }} catch {{ "FAILED`t$iso`t$($_.Exception.Message)" }}
}}
foreach ($volume in Get-Volume) {{
    if (-not $volume.DriveLetter) {{ continue }}
    foreach ($name in 'install.wim', 'install.esd') {{
        $file = "$($volume.DriveLetter):\sources\$name"
        if (-not (Test-Path -LiteralPath $file)) {{ continue }}
        try {{
            foreach ($entry in Get-WindowsImage -ImagePath $file -ErrorAction Stop) {{
                $image = Get-WindowsImage -ImagePath $file -Index $entry.ImageIndex -ErrorAction Stop
                "IMAGE`t$($image.ImageIndex)`t$($image.EditionId)`t$($image.Version)`t$($image.Languages -join ',')`t$file"
            }}
        }} catch {{ "FAILED`t$file`t$($_.Exception.Message)" }}
    }}
}}"#,
        isos = ps_list(&isos)
    )
}

/// Unmounts the ISOs [`find_script`] mounted.
pub fn dismount_script(isos: &[String]) -> String {
    format!(
        "foreach ($iso in {}) {{ Dismount-DiskImage -ImagePath $iso -ErrorAction SilentlyContinue | Out-Null }}",
        ps_list(isos)
    )
}

/// The Windows this PC runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThisWindows {
    pub edition: String,
    pub build: u32,
    pub display_version: String,
}

impl ThisWindows {
    /// Windows 11 starts at build 22000; ProductName says "Windows 10" on it
    /// still.
    fn is_windows_11(&self) -> bool {
        self.build >= 22000
    }

    /// "Windows 11 25H2 (build 26200)", for telling the user which ISO fits.
    pub fn describe(&self) -> String {
        let name = if self.is_windows_11() {
            "Windows 11"
        } else {
            "Windows 10"
        };
        format!("{name} {} (build {})", self.display_version, self.build)
    }

    /// The page on microsoft.com/software-download/ that offers its ISO.
    pub fn download_page(&self) -> &'static str {
        if self.is_windows_11() {
            "windows11"
        } else {
            "windows10"
        }
    }
}

/// One Windows image on installation media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaImage {
    pub index: u32,
    pub edition: String,
    pub version: String,
    pub languages: String,
    /// `D:\sources\install.wim`
    pub file: String,
}

impl MediaImage {
    fn build(&self) -> Option<u32> {
        self.version.split('.').nth(2)?.parse().ok()
    }

    fn version_key(&self) -> Vec<u32> {
        self.version
            .split('.')
            .filter_map(|part| part.parse().ok())
            .collect()
    }

    /// DISM's `/Source` for this image, `/Source:wim:D:\sources\install.wim:6`.
    pub fn dism_source(&self) -> String {
        let kind = if self.file.to_ascii_lowercase().ends_with(".esd") {
            "esd"
        } else {
            "wim"
        };
        format!("/Source:{kind}:{}:{}", self.file, self.index)
    }
}

/// What [`find_script`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Media {
    pub windows: Option<ThisWindows>,
    pub images: Vec<MediaImage>,
    /// The ISOs the script mounted, to unmount again.
    pub mounted: Vec<String>,
    /// Drive letter and ISO of every mounted ISO.
    pub isos: Vec<(char, String)>,
    /// What could not be mounted or read, for the log.
    pub failed: Vec<String>,
}

impl Media {
    pub fn parse(stdout: &str) -> Self {
        let mut media = Media::default();
        for line in stdout.lines() {
            let fields: Vec<&str> = line.trim_end().split('\t').collect();
            match fields.as_slice() {
                ["WINDOWS", edition, build, display_version] => {
                    if let Ok(build) = build.parse() {
                        media.windows = Some(ThisWindows {
                            edition: edition.to_string(),
                            build,
                            display_version: display_version.to_string(),
                        });
                    }
                }
                ["MOUNTED", iso] => media.mounted.push(iso.to_string()),
                ["ISO", letter, iso] => {
                    if let Some(letter) = letter.chars().next() {
                        media.isos.push((letter, iso.to_string()));
                    }
                }
                ["IMAGE", index, edition, version, languages, file] => {
                    if let Ok(index) = index.parse() {
                        media.images.push(MediaImage {
                            index,
                            edition: edition.to_string(),
                            version: version.to_string(),
                            languages: languages.to_string(),
                            file: file.to_string(),
                        });
                    }
                }
                ["FAILED", what, message] => media.failed.push(format!("{what}: {message}")),
                _ => {}
            }
        }
        media
    }

    /// The image to repair from: one of this PC's edition, from the same
    /// build if there is one, the newest otherwise. DISM decides whether its
    /// files fit.
    pub fn best(&self) -> Option<&MediaImage> {
        let windows = self.windows.as_ref()?;
        self.images
            .iter()
            .filter(|image| image.edition.eq_ignore_ascii_case(&windows.edition))
            .max_by_key(|image| (image.build() == Some(windows.build), image.version_key()))
    }

    /// Where `image` came from, as the user knows it: the ISO's file name,
    /// or the drive of a USB stick or DVD.
    pub fn origin(&self, image: &MediaImage) -> String {
        let letter = image.file.chars().next().map(|c| c.to_ascii_uppercase());
        self.isos
            .iter()
            .find(|(drive, _)| Some(drive.to_ascii_uppercase()) == letter)
            .map(|(_, iso)| iso.rsplit('\\').next().unwrap_or(iso).to_string())
            .unwrap_or_else(|| format!("drive {}:", letter.unwrap_or('?')))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::decode::decode_output;

    // What `find_script` printed, elevated, for the German 25H2 ISO from
    // microsoft.com; see tests/fixtures/README.md.
    const MOUNTED_IT: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_install_media_mount.bin");
    const MOUNTED_ALREADY: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_install_media_mounted.bin");
    const NOT_AN_ISO: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_install_media_not_an_iso.bin");
    const ISO: &str = r"C:\Users\user\Downloads\Win11_25H2_German_x64_v2.iso";

    const THIS_PC: &str = "WINDOWS\tProfessional\t26200\t25H2\r\n";

    /// An `IMAGE` line in the captured shape, for media no capture has.
    fn image_line(index: u32, edition: &str, version: &str, file: &str) -> String {
        format!("IMAGE\t{index}\t{edition}\t{version}\tde-DE\t{file}\r\n")
    }

    #[test]
    fn dism_exits_with_the_hresult_it_prints() {
        // Captured: "Error: 0x800f0915" exited -2146498283, "Error: 11" 11.
        let missing = CmdOutput::with_output(-2146498283, "", "");
        assert!(source_missing(&missing));
        let not_found = CmdOutput::with_output(0x800F_081Fu32 as i32, "", "");
        assert!(source_missing(&not_found));
        assert!(!source_missing(&CmdOutput::with_output(11, "", "")));
        assert!(!source_missing(&CmdOutput::with_output(740, "", "")));
        assert!(!source_missing(&CmdOutput::ok("")));
    }

    #[test]
    fn the_pro_image_of_the_captured_iso_is_chosen() {
        let media = Media::parse(&decode_output(MOUNTED_IT));
        assert_eq!(
            media.windows,
            Some(ThisWindows {
                edition: "Professional".to_string(),
                build: 26200,
                display_version: "25H2".to_string(),
            })
        );
        assert_eq!(media.mounted, vec![ISO.to_string()]);
        assert_eq!(media.images.len(), 10);
        // Not ProfessionalN, ProfessionalEducation or ProfessionalWorkstation.
        let best = media.best().expect("the ISO has a Pro image");
        assert_eq!(best.index, 5);
        assert_eq!(best.version, "10.0.26200.8037");
        assert_eq!(best.dism_source(), r"/Source:wim:D:\sources\install.wim:5");
        assert_eq!(media.origin(best), "Win11_25H2_German_x64_v2.iso");
    }

    #[test]
    fn an_iso_the_user_mounted_is_left_mounted() {
        let media = Media::parse(&decode_output(MOUNTED_ALREADY));
        assert!(media.mounted.is_empty());
        assert_eq!(media.isos, vec![('D', ISO.to_string())]);
        assert_eq!(media.best().map(|image| image.index), Some(5));
    }

    #[test]
    fn a_file_that_is_no_iso_does_not_stop_the_search() {
        // The real ISO was still mounted from the capture before, so it is
        // found as a drive, not by its name.
        let media = Media::parse(&decode_output(NOT_AN_ISO));
        assert_eq!(
            media.failed,
            vec![
                r"C:\Users\user\Desktop\winmedic-capture\out\not-an-iso.iso: Die Datei oder das Verzeichnis ist beschädigt und nicht lesbar."
                    .to_string()
            ]
        );
        assert!(media.mounted.is_empty());
        let best = media.best().unwrap();
        assert_eq!(media.origin(best), "drive D:");
    }

    #[test]
    fn the_image_of_this_build_comes_first() {
        let media = Media::parse(&format!(
            "{THIS_PC}{}{}",
            image_line(
                5,
                "Professional",
                "10.0.26300.100",
                r"E:\sources\install.wim"
            ),
            image_line(
                6,
                "Professional",
                "10.0.26200.6584",
                r"F:\sources\install.wim"
            ),
        ));
        assert_eq!(
            media.best().unwrap().dism_source(),
            r"/Source:wim:F:\sources\install.wim:6"
        );
    }

    #[test]
    fn without_this_build_the_newest_image_is_tried() {
        let media = Media::parse(&format!(
            "{THIS_PC}{}{}",
            image_line(
                6,
                "Professional",
                "10.0.26100.1742",
                r"E:\sources\install.wim"
            ),
            image_line(
                4,
                "Professional",
                "10.0.26100.4349",
                r"F:\sources\install.esd"
            ),
        ));
        let best = media.best().unwrap();
        assert_eq!(best.dism_source(), r"/Source:esd:F:\sources\install.esd:4");
        assert_eq!(media.origin(best), "drive F:");
    }

    #[test]
    fn media_without_this_edition_is_no_source() {
        let enterprise =
            decode_output(MOUNTED_IT).replace("WINDOWS\tProfessional", "WINDOWS\tEnterprise");
        let media = Media::parse(&enterprise);
        assert_eq!(media.best(), None);
        assert_eq!(media.images.len(), 10);
    }

    #[test]
    fn this_windows_is_named_the_way_the_download_page_does() {
        let media = Media::parse(THIS_PC);
        assert_eq!(
            media.windows.unwrap().describe(),
            "Windows 11 25H2 (build 26200)"
        );
    }

    #[test]
    fn isos_are_quoted_into_the_scripts() {
        let script = find_script(&[PathBuf::from(r"C:\Users\O'Brien\Downloads\win.iso")]);
        assert!(
            script.contains(r"foreach ($iso in @('C:\Users\O''Brien\Downloads\win.iso'))"),
            "{script}"
        );
        assert!(find_script(&[]).contains("foreach ($iso in @())"));
        assert_eq!(
            dismount_script(&[r"C:\a.iso".to_string()]),
            r"foreach ($iso in @('C:\a.iso')) { Dismount-DiskImage -ImagePath $iso -ErrorAction SilentlyContinue | Out-Null }"
        );
    }

    #[test]
    fn only_isos_are_taken_from_downloads_the_newest_first() {
        let folder = std::env::temp_dir().join(format!("winmedic-isos-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let old = folder.join("old.ISO");
        let new = folder.join("new.iso");
        std::fs::write(&old, b"").unwrap();
        std::fs::write(folder.join("notes.txt"), b"").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&new, b"").unwrap();
        let isos = isos_in(&folder);
        let _ = std::fs::remove_dir_all(&folder);
        assert_eq!(isos, vec![new, old]);
    }
}
