//! A command, and whatever it starts, ends with WinMedic while WinMedic waits
//! for it, however WinMedic ends.
//!
//! `kill_on_drop` ends a command when the future that waits for it is
//! dropped, as a cancelled scan does. That needs WinMedic to drop the future.
//! Ended by an abort (a panic in the release build), a crash or in Task
//! Manager, WinMedic drops nothing, and the command runs on where nobody sees
//! it: the DISM of each scan 0.10.0 crashed in kept going for hours, with its
//! DismHost (#223). So each command runs in a job object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` whose only handle WinMedic holds.
//! Windows closes that handle when WinMedic ends, however it ends, and ends
//! every process in the job, the ones the command started included.
//!
//! One job per command, not one for all: a command that has ended by itself
//! may leave a process running on purpose - the icon cache repair starts
//! Explorer again when Windows has not - and that one has to outlive WinMedic.
//! Such a job is let go ([`Job::let_go`]) once its command has ended.

/// A job object whose processes end when WinMedic ends.
#[derive(Debug)]
pub struct Job {
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}

/// The creation flag that starts a process suspended, for [`Job::adopt`].
#[cfg(windows)]
pub const CREATE_SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

#[cfg(windows)]
impl Job {
    /// A new, empty job whose processes end when its handle is closed.
    ///
    /// A process in it that asks to leave it (`CREATE_BREAKAWAY_FROM_JOB`)
    /// may: refused, its start would fail.
    pub fn new() -> std::io::Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        // SAFETY: no security attributes, so the handle is not inherited by
        // the processes WinMedic starts, and no name.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a handle just created, owned by nothing else.
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
        };
        job.limit(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK)?;
        Ok(job)
    }

    /// Put `process`, started with [`CREATE_SUSPENDED`], into the job, then
    /// let it run. Suspended, it cannot start anything before it is in the
    /// job: DISM starts DismHost at once.
    ///
    /// `Ok(false)` when Windows did not put it into the job; it runs all the
    /// same, as every command did before. Only a process that cannot be let
    /// run is an error.
    pub fn adopt(
        &self,
        process: std::os::windows::io::BorrowedHandle<'_>,
    ) -> std::io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: two live handles: the job's and the process's.
        let adopted = unsafe {
            AssignProcessToJobObject(self.handle.as_raw_handle(), process.as_raw_handle())
        } != FALSE;
        resume(process)?;
        Ok(adopted)
    }

    /// Let the processes in the job run on once its handle is closed: what a
    /// command that has ended by itself left running is meant to run.
    pub fn let_go(&self) -> std::io::Result<()> {
        self.limit(windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_BREAKAWAY_OK)
    }

    fn limit(
        &self,
        flags: windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT,
    ) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = flags;
        // SAFETY: a live job handle, and a structure of the class and size
        // given that lives for the call.
        let set = unsafe {
            SetInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Let a process started suspended run.
///
/// The standard library keeps the handle of a new process's first thread to
/// itself (`ChildExt::main_thread_handle` is unstable), and looking the thread
/// up in a Toolhelp snapshot, a walk over every thread on the machine, took
/// 27 ms a command on the development PC. `NtResumeProcess` resumes the
/// process's threads in one call. It is not in the SDK's headers, but ntdll
/// exports it on every Windows WinMedic runs on.
#[cfg(windows)]
fn resume(process: std::os::windows::io::BorrowedHandle<'_>) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;

    #[link(name = "ntdll", kind = "raw-dylib")]
    unsafe extern "system" {
        fn NtResumeProcess(process: *mut std::ffi::c_void) -> i32;
    }

    // SAFETY: a live handle of the process, with the access CreateProcess
    // gives it.
    let status = unsafe { NtResumeProcess(process.as_raw_handle().cast()) };
    if status < 0 {
        // SAFETY: takes a plain value.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

#[cfg(not(windows))]
impl Job {
    pub fn new() -> std::io::Result<Self> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub fn let_go(&self) -> std::io::Result<()> {
        Ok(())
    }
}
