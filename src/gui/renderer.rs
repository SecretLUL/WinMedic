//! What the window draws with: Direct3D 12, through wgpu.
//!
//! Every Windows 10 and 11 has Direct3D 12, and with it WARP, Windows' own
//! software renderer (the "Microsoft Basic Render Driver"), which Windows
//! lists after the graphics cards. wgpu creates a device on each adapter and
//! keeps only those where that works. So a graphics card draws the window
//! where it can, and WARP, slower but whole, where none does: the Microsoft
//! Basic Display Adapter after a driver crash, a virtual machine, a remote
//! session.
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

use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetupCreateNew};
use eframe::wgpu;

/// eframe's wgpu settings, with the instance and the choice of adapter made
/// here.
pub fn wgpu_configuration() -> WgpuConfiguration {
    WgpuConfiguration {
        wgpu_setup: setup().into(),
        ..eframe::NativeOptions::default().wgpu_options
    }
}

/// Direct3D 12 and nothing else, every setting spelt out.
fn setup() -> WgpuSetupCreateNew {
    WgpuSetupCreateNew {
        instance_descriptor: instance_descriptor(),
        display_handle: None,
        // The order Windows lists the adapters in: the one the main screen is
        // on first, WARP last. A power preference would pick a laptop's other
        // graphics card, or a desktop's integrated one, to draw for a screen
        // it does not drive.
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
                // FXC is d3dcompiler_47.dll, which Windows has in System32.
                // DXC would be a dxcompiler.dll from wherever one is found.
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
    use eframe::egui_wgpu::WgpuSetup;

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
    fn the_setup_takes_nothing_from_the_environment() {
        let setup = setup();
        let instance = &setup.instance_descriptor;
        assert_eq!(instance.backends, wgpu::Backends::DX12);
        assert_eq!(instance.flags, wgpu::InstanceFlags::from_build_config());
        let dx12 = &instance.backend_options.dx12;
        assert!(matches!(dx12.shader_compiler, wgpu::Dx12Compiler::Fxc));
        assert!(dx12.agility_sdk.is_none());
        assert_eq!(setup.power_preference, wgpu::PowerPreference::None);
        assert!(setup.native_adapter_selector.is_none());

        assert!(matches!(
            wgpu_configuration().wgpu_setup,
            WgpuSetup::CreateNew(ref chosen)
                if chosen.instance_descriptor.backends == wgpu::Backends::DX12
        ));
    }

    /// What a PC without a working graphics driver gets: Windows' software
    /// renderer, and on it the device the window draws with. No window and
    /// no surface; on CI, a virtual machine without a graphics card, this is
    /// the only adapter there is.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_software_renderer_gives_a_device() {
        let setup = setup();
        let adapter = wgpu::Instance::new(instance_descriptor())
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: setup.power_preference,
                force_fallback_adapter: true,
                compatible_surface: None,
                apply_limit_buckets: false,
            })
            .await
            .expect("Windows lists WARP as a Direct3D 12 adapter");
        assert_eq!(adapter.get_info().device_type, wgpu::DeviceType::Cpu);

        adapter
            .request_device(&(setup.device_descriptor)(&adapter))
            .await
            .expect("WARP creates the device the window draws with");
    }
}
