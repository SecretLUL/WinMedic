//! The devices Windows knows, asked of its device manager directly.
//!
//! WMI's `Win32_PnPEntity` has the same problem codes, but reaching it takes a
//! PowerShell start and a WMI provider. On a busy CI runner that did not
//! answer within twice 30 seconds, and a PC whose WMI is broken - which
//! WinMedic diagnoses - would not answer at all. SetupAPI and CfgMgr32 answer
//! in milliseconds, without either.

/// A device that is connected now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnpDevice {
    /// The problem code Device Manager shows (`CM_PROB_*`), 0 when it works.
    pub problem: u32,
    /// The setup class; empty for a device without a driver, whose driver
    /// would bring it.
    pub class: String,
    pub instance_id: String,
    /// The friendly name, else the description; empty for some devices
    /// without a driver.
    pub name: String,
}

/// Every device that is connected now, with its problem code.
#[cfg(windows)]
pub fn connected_devices() -> Result<Vec<PnpDevice>, String> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_DevNode_Status, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT, DN_HAS_PROBLEM,
        SP_DEVINFO_DATA, SPDRP_CLASS, SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME,
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW,
    };

    // SAFETY: every pointer handed to SetupAPI and CfgMgr32 points at a live
    // local of the size the call is told; the device information set is
    // destroyed exactly once, after the last use of it.
    unsafe {
        let set = SetupDiGetClassDevsW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );
        if set == -1 {
            return Err(format!(
                "Windows did not list its devices: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut devices = Vec::new();
        for index in 0.. {
            let mut info: SP_DEVINFO_DATA = std::mem::zeroed();
            info.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiEnumDeviceInfo(set, index, &mut info) == 0 {
                break;
            }

            // Device instance IDs are at most 200 characters.
            let mut id = [0u16; 256];
            if SetupDiGetDeviceInstanceIdW(
                set,
                &info,
                id.as_mut_ptr(),
                id.len() as u32,
                std::ptr::null_mut(),
            ) == 0
            {
                continue;
            }

            let (mut status, mut problem) = (0u32, 0u32);
            let has_problem = CM_Get_DevNode_Status(&mut status, &mut problem, info.DevInst, 0)
                == CR_SUCCESS
                && status & DN_HAS_PROBLEM != 0;

            let text = |property| registry_text(set, &info, property);
            devices.push(PnpDevice {
                problem: if has_problem { problem } else { 0 },
                class: text(SPDRP_CLASS).unwrap_or_default(),
                instance_id: utf16_until_nul(&id),
                name: text(SPDRP_FRIENDLYNAME)
                    .or_else(|| text(SPDRP_DEVICEDESC))
                    .unwrap_or_default(),
            });
        }

        SetupDiDestroyDeviceInfoList(set);
        Ok(devices)
    }
}

#[cfg(not(windows))]
pub fn connected_devices() -> Result<Vec<PnpDevice>, String> {
    Ok(Vec::new())
}

/// A text property of a device, `None` when it has none.
///
/// # Safety
///
/// `set` must be a live device information set and `info` one of its members.
#[cfg(windows)]
unsafe fn registry_text(
    set: windows_sys::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    info: &windows_sys::Win32::Devices::DeviceAndDriverInstallation::SP_DEVINFO_DATA,
    property: u32,
) -> Option<String> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceRegistryPropertyW;

    let mut buffer = [0u16; 512];
    // SAFETY: the buffer is as large as the size passed, in bytes.
    let found = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            info,
            property,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            std::ptr::null_mut(),
        )
    };
    let text = utf16_until_nul(&buffer);
    (found != 0 && !text.is_empty()).then_some(text)
}

fn utf16_until_nul(units: &[u16]) -> String {
    let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_ends_at_the_first_nul() {
        let units: Vec<u16> = "Brio 500\0junk".encode_utf16().collect();
        assert_eq!(utf16_until_nul(&units), "Brio 500");
        assert_eq!(utf16_until_nul(&[]), "");
    }

    /// Reads, changes nothing: every Windows has devices, and each has an
    /// instance ID.
    #[cfg(windows)]
    #[test]
    fn windows_lists_its_devices() {
        let devices = connected_devices().unwrap();
        assert!(!devices.is_empty());
        assert!(devices.iter().all(|d| !d.instance_id.is_empty()));
    }
}
