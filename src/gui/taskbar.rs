//! How far a scan or a repair run got, on WinMedic's taskbar button.
//!
//! A scan takes minutes and a repair run can take a quarter of an hour, and a
//! window nobody watches that long gets minimised. Windows lets a taskbar
//! button carry a progress bar for exactly that (`ITaskbarList3`): the button
//! fills as the run gets on and is plain again once it is over.

use crate::app::App;
use raw_window_handle::HasWindowHandle;

/// What the taskbar button shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Nothing runs: no bar.
    Idle,
    /// A run that has not got anywhere yet, such as a repair run creating its
    /// restore point: a bar that keeps moving, so the button still says that
    /// something is happening.
    Starting,
    /// A run this many percent along.
    Percent(u8),
}

impl Progress {
    /// The bar for what `app` is doing: the same fraction the window's own
    /// progress bar shows.
    pub fn of(app: &App) -> Self {
        let fraction = if app.is_scanning {
            f32::from(app.scan_overall_progress) / 100.0
        } else if app.is_fixing {
            app.repair_fraction()
        } else {
            return Self::Idle;
        };
        match (fraction.clamp(0.0, 1.0) * 100.0).round() as u8 {
            0 => Self::Starting,
            percent => Self::Percent(percent),
        }
    }
}

/// The taskbar button of WinMedic's window.
pub struct Taskbar {
    button: Option<com::Button>,
    shown: Progress,
}

impl Taskbar {
    /// The button of `window`. Without one to talk to — a window handle that
    /// is not Win32, or a shell with no taskbar — it does nothing.
    pub fn of(window: &impl HasWindowHandle) -> Self {
        let button = match window.window_handle().map(|handle| handle.as_raw()) {
            #[cfg(windows)]
            Ok(raw_window_handle::RawWindowHandle::Win32(handle)) => {
                com::Button::new(handle.hwnd.get())
            }
            _ => None,
        };
        Self {
            button,
            shown: Progress::Idle,
        }
    }

    /// Show `progress`. Called every frame, it talks to the taskbar only when
    /// the bar changes.
    ///
    /// Windows drops a bar set before the button exists, in a window's first
    /// moments, and when Explorer restarts. Neither costs a run its bar: one
    /// starts only when the user asks, and a bar lost to Explorer comes back
    /// with the run's next step.
    pub fn show(&mut self, progress: Progress) {
        if progress == self.shown {
            return;
        }
        self.shown = progress;
        if let Some(button) = &self.button {
            button.show(progress);
        }
    }
}

#[cfg(windows)]
mod com {
    use super::Progress;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows_sys::Win32::UI::Shell::{
        TBPF_INDETERMINATE, TBPF_NOPROGRESS, TBPFLAG, TaskbarList,
    };
    use windows_sys::core::{GUID, HRESULT};

    /// `ITaskbarList3`, as shobjidl_core.h declares it.
    const IID_ITASKBARLIST3: GUID = GUID::from_u128(0xea1afb91_9e28_4b86_90e9_9e9f8a5eefaf);

    /// `ITaskbarList3`'s function table as far as the entries used here, in
    /// the order the header declares them: `IUnknown`, `ITaskbarList`,
    /// `ITaskbarList2`, then its own. windows-sys has the class and the flags
    /// but no COM interfaces.
    #[repr(C)]
    struct Vtbl {
        /// `QueryInterface`, `AddRef`.
        _unknown: [usize; 2],
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        hr_init: unsafe extern "system" fn(*mut c_void) -> HRESULT,
        /// `AddTab`, `DeleteTab`, `ActivateTab`, `SetActiveAlt`,
        /// `MarkFullscreenWindow`.
        _tabs: [usize; 5],
        set_progress_value: unsafe extern "system" fn(*mut c_void, HWND, u64, u64) -> HRESULT,
        set_progress_state: unsafe extern "system" fn(*mut c_void, HWND, TBPFLAG) -> HRESULT,
    }

    /// An `ITaskbarList3` on one window, used from the window's thread.
    pub(super) struct Button {
        list: *mut c_void,
        window: HWND,
        /// Whether `CoInitializeEx` succeeded and wants its `CoUninitialize`.
        com: bool,
    }

    impl Button {
        /// The button of the window `hwnd` names.
        pub(super) fn new(hwnd: isize) -> Option<Self> {
            let mut button = Self {
                list: std::ptr::null_mut(),
                window: hwnd as HWND,
                com: false,
            };
            // winit has usually initialised COM on the window's thread
            // already, for drag and drop; then this only counts it once more.
            button.com =
                unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) } >= 0;
            let created = unsafe {
                CoCreateInstance(
                    &TaskbarList,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_ITASKBARLIST3,
                    &mut button.list,
                )
            };
            if created < 0 {
                button.list = std::ptr::null_mut();
                return None;
            }
            if button.list.is_null() || unsafe { (button.vtbl().hr_init)(button.list) } < 0 {
                return None;
            }
            Some(button)
        }

        fn vtbl(&self) -> &Vtbl {
            // A COM object starts with a pointer to its function table.
            unsafe { &**(self.list as *const *const Vtbl) }
        }

        /// Put `progress` on the button. A failure leaves the button as it
        /// was: the bar is a courtesy, nothing depends on it.
        pub(super) fn show(&self, progress: Progress) {
            let vtbl = self.vtbl();
            unsafe {
                match progress {
                    Progress::Idle => {
                        (vtbl.set_progress_state)(self.list, self.window, TBPF_NOPROGRESS)
                    }
                    Progress::Starting => {
                        (vtbl.set_progress_state)(self.list, self.window, TBPF_INDETERMINATE)
                    }
                    // Leaves the moving bar for a normal one by itself.
                    Progress::Percent(percent) => {
                        (vtbl.set_progress_value)(self.list, self.window, u64::from(percent), 100)
                    }
                };
            }
        }
    }

    impl Drop for Button {
        fn drop(&mut self) {
            if !self.list.is_null() {
                unsafe { (self.vtbl().release)(self.list) };
            }
            if self.com {
                unsafe { CoUninitialize() };
            }
        }
    }
}

#[cfg(not(windows))]
mod com {
    pub(super) struct Button;

    impl Button {
        pub(super) fn show(&self, _: super::Progress) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The button follows the window's own bar: nothing while idle, a moving
    /// bar until a run has got anywhere, then how far it got.
    #[test]
    fn the_button_shows_how_far_a_scan_or_a_repair_run_got() {
        let mut app = App::new();
        assert_eq!(Progress::of(&app), Progress::Idle);

        app.is_scanning = true;
        assert_eq!(Progress::of(&app), Progress::Starting);
        app.scan_overall_progress = 40;
        assert_eq!(Progress::of(&app), Progress::Percent(40));

        app.is_scanning = false;
        app.is_fixing = true;
        app.total_to_fix = 4;
        assert_eq!(Progress::of(&app), Progress::Starting);
        app.fixed_count = 1;
        assert_eq!(Progress::of(&app), Progress::Percent(25));

        app.is_fixing = false;
        assert_eq!(Progress::of(&app), Progress::Idle);
    }
}
