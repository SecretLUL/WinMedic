//! What the window draws with: Direct3D 12, through wgpu.
//!
//! Every Windows 10 and 11 has Direct3D 12, and with it WARP, Windows' own
//! software renderer (the "Microsoft Basic Render Driver"). The window's
//! device is made before the window: on the first graphics card that gives
//! one, in the order Windows lists them, and on WARP when none does. So a
//! graphics card draws the window where it can, and WARP, slower but whole,
//! where none can: the Microsoft Basic Display Adapter after a driver crash, a
//! virtual machine, a remote session, a driver that fails. wgpu leaves out
//! cards below its minimum as well (resource binding tier 2; Intel's Haswell
//! graphics), and those draw with WARP too.
//!
//! The window used to draw with OpenGL, which those PCs do not offer, and
//! neither does one whose OpenGL driver is registered at a file that is gone.
//! It did not open on the machines WinMedic is for.
//!
//! Nothing here comes from the environment. egui-wgpu's defaults read `WGPU_*`
//! variables, one of which (`WGPU_DX12_AGILITY_SDK_PATH`) loads a Direct3D
//! runtime from any folder, and a variable set for the user reaches WinMedic
//! running as Administrator: the same way in as a DLL put beside the
//! executable, which `main` already shuts.

use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetupCreateNew, WgpuSetupExisting};
use eframe::wgpu;

/// eframe's wgpu settings, with the instance, the adapter and the device
/// made here.
pub fn wgpu_configuration() -> WgpuConfiguration {
    WgpuConfiguration {
        wgpu_setup: match device_up_front() {
            Some(device) => device.into(),
            // Not even WARP gave one. eframe tries again with the same
            // settings and says why it failed, and the window's message box
            // takes it from there.
            None => setup().into(),
        },
        ..eframe::NativeOptions::default().wgpu_options
    }
}

/// The device the window draws with, made before the window, or `None` when
/// no adapter gives one, WARP included.
///
/// Left to eframe, the first adapter Windows lists would be asked once
/// (egui-wgpu calls `request_device` a single time): a graphics card whose
/// driver passes the listing but fails the device would keep the window shut
/// while WARP was there.
fn device_up_front() -> Option<WgpuSetupExisting> {
    let instance = wgpu::Instance::new(instance_descriptor());
    let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::DX12));
    first_device(instance, adapters)
}

fn first_device(
    instance: wgpu::Instance,
    adapters: Vec<wgpu::Adapter>,
) -> Option<WgpuSetupExisting> {
    let describe = setup().device_descriptor;
    let (adapter, (device, queue)) = first_that_opens(
        adapters,
        |adapter| adapter.get_info().device_type == wgpu::DeviceType::Cpu,
        |adapter| pollster::block_on(adapter.request_device(&describe(adapter))).ok(),
    )?;
    Some(WgpuSetupExisting {
        instance,
        adapter,
        device,
        queue,
    })
}

/// The first of `adapters` that `open` succeeds on, and what it gave: the
/// graphics cards in the order given, then the software renderers, wherever
/// those were listed.
fn first_that_opens<A, D>(
    adapters: Vec<A>,
    is_software: impl Fn(&A) -> bool,
    mut open: impl FnMut(&A) -> Option<D>,
) -> Option<(A, D)> {
    let (software, cards): (Vec<A>, Vec<A>) = adapters.into_iter().partition(&is_software);
    cards
        .into_iter()
        .chain(software)
        .find_map(|adapter| open(&adapter).map(|opened| (adapter, opened)))
}

/// Direct3D 12 and nothing else, every setting spelt out.
fn setup() -> WgpuSetupCreateNew {
    WgpuSetupCreateNew {
        instance_descriptor: instance_descriptor(),
        display_handle: None,
        // Only for eframe's second try, when no adapter gave a device up
        // front: the order Windows lists the adapters in. A power preference
        // would pick a laptop's other graphics card, or a desktop's integrated
        // one, to draw for a screen it does not drive.
        power_preference: wgpu::PowerPreference::None,
        native_adapter_selector: None,
        // egui's own: the limits its renderer needs.
        device_descriptor: WgpuSetupCreateNew::without_display_handle().device_descriptor,
    }
}

fn instance_descriptor() -> wgpu::InstanceDescriptor {
    wgpu::InstanceDescriptor {
        backends: wgpu::Backends::DX12,
        flags: wgpu::InstanceFlags::from_build_config(),
        memory_budget_thresholds: wgpu::MemoryBudgetThresholds::default(),
        backend_options: wgpu::BackendOptions {
            dx12: wgpu::Dx12BackendOptions {
                // FXC is d3dcompiler_47.dll, which every Windows 10 and 11 has
                // in System32. DXC is not part of Windows.
                shader_compiler: wgpu::Dx12Compiler::Fxc,
                agility_sdk: None,
                ..Default::default()
            },
            ..Default::default()
        },
        display: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cargo.toml switches Direct3D 12 on through a wgpu of its own. Raised
    /// without eframe, or eframe without it, there are two in the tree, and
    /// eframe's has no backend at all: the window would find no adapter.
    #[cfg(windows)]
    #[test]
    fn direct3d_12_is_the_only_backend_built_in() {
        assert_eq!(
            wgpu::Instance::enabled_backend_features(),
            wgpu::Backends::DX12
        );
    }

    #[test]
    fn every_setting_is_spelt_out() {
        let setup = setup();
        let instance = &setup.instance_descriptor;
        assert_eq!(instance.backends, wgpu::Backends::DX12);
        assert_eq!(instance.flags, wgpu::InstanceFlags::from_build_config());
        let dx12 = &instance.backend_options.dx12;
        assert!(matches!(dx12.shader_compiler, wgpu::Dx12Compiler::Fxc));
        assert!(dx12.agility_sdk.is_none());
        assert_eq!(setup.power_preference, wgpu::PowerPreference::None);
        assert!(setup.native_adapter_selector.is_none());
    }

    /// (name, is the software renderer)
    type Listed = (&'static str, bool);

    fn software(adapter: &Listed) -> bool {
        adapter.1
    }

    /// Windows lists WARP last, but nothing here relies on it.
    #[test]
    fn a_graphics_card_comes_before_the_software_renderer() {
        let listed: Vec<Listed> = vec![("WARP", true), ("card", false), ("second card", false)];
        let opened = first_that_opens(listed, software, |adapter| Some(adapter.0));
        assert_eq!(opened.map(|(_, device)| device), Some("card"));
    }

    #[test]
    fn a_card_that_gives_no_device_leaves_it_to_the_next_and_then_to_warp() {
        let listed: Vec<Listed> = vec![("card", false), ("WARP", true), ("second card", false)];
        let mut asked = Vec::new();
        let opened = first_that_opens(listed, software, |adapter| {
            asked.push(adapter.0);
            adapter.1.then_some(adapter.0)
        });
        assert_eq!(opened.map(|(_, device)| device), Some("WARP"));
        assert_eq!(asked, ["card", "second card", "WARP"]);
    }

    #[test]
    fn no_device_anywhere_is_none() {
        let listed: Vec<Listed> = vec![("card", false), ("WARP", true)];
        assert!(first_that_opens(listed, software, |_| None::<()>).is_none());
    }

    /// What a PC without a working graphics driver gets: the device from
    /// Windows' software renderer, and on it egui's shader, compiled by FXC,
    /// and its pipeline. No window and no surface. Listing the adapters makes
    /// a device on each, as every Direct3D program does, but only WARP's is
    /// kept and drawn with; on CI, a virtual machine without a graphics card,
    /// WARP is all there is.
    #[cfg(windows)]
    #[test]
    fn windows_software_renderer_draws_egui() {
        let instance = wgpu::Instance::new(instance_descriptor());
        let warp: Vec<wgpu::Adapter> =
            pollster::block_on(instance.enumerate_adapters(wgpu::Backends::DX12))
                .into_iter()
                .filter(|adapter| adapter.get_info().device_type == wgpu::DeviceType::Cpu)
                .collect();
        assert!(
            !warp.is_empty(),
            "Windows lists WARP as a Direct3D 12 adapter"
        );

        let made = first_device(instance, warp).expect("WARP gives the window its device");
        assert_eq!(made.adapter.get_info().device_type, wgpu::DeviceType::Cpu);
        eframe::egui_wgpu::Renderer::new(
            &made.device,
            wgpu::TextureFormat::Bgra8Unorm,
            eframe::egui_wgpu::RendererOptions::default(),
        );
    }
}
