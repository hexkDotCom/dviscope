//! Windows supervision primitives: process creation inside a Job Object
//! (no window between creation and job membership), console control events, process
//! identity, write-through renames, owner-only directories. The only module of the
//! workspace allowed to use `unsafe`; every block states why it is sound.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

/// A Job Object owning a supervised process tree; terminating or closing it (also by the
/// supervisor's death: kill-on-close) ends every process in it.
#[derive(Debug)]
pub struct Job {
    handle: HANDLE,
}

// SAFETY: a job handle is a kernel object handle usable from any thread.
unsafe impl Send for Job {}

impl Job {
    /// A new job with kill-on-close (handle not inheritable).
    ///
    /// # Errors
    /// The OS error.
    pub fn new() -> io::Result<Self> {
        // SAFETY: null attributes (default security, non-inheritable) and no name.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        // SAFETY: a zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION is valid plain data.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the pointer and size describe `info`, alive across the call.
        let ok = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast::<c_void>(),
                u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Ends every process of the job. Returns the OS error when it fails.
    pub fn terminate(&self, code: u32) -> Option<io::Error> {
        // SAFETY: valid job handle.
        let ok = unsafe { TerminateJobObject(self.handle, code) };
        (ok == 0).then(io::Error::last_os_error)
    }

    /// Total user + kernel CPU seconds of every process ever in the job.
    #[must_use]
    pub fn cpu_seconds(&self) -> Option<f64> {
        // SAFETY: zeroed plain data.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer and size describe `info`; the return length may be null.
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut info).cast::<c_void>(),
                u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX),
                std::ptr::null_mut(),
            )
        };
        #[allow(clippy::cast_precision_loss)] // CPU seconds as a measure (100 ns units)
        (ok != 0).then(|| (info.TotalUserTime + info.TotalKernelTime) as f64 / 1e7)
    }

    /// Peak memory of the largest single process of the job, KiB.
    #[must_use]
    pub fn peak_process_kb(&self) -> Option<u64> {
        // SAFETY: zeroed plain data.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer and size describe `info`.
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_mut(&mut info).cast::<c_void>(),
                u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some((info.PeakProcessMemoryUsed / 1024) as u64)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and closed once.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Quotes one argument for a Windows command line (the rules `CommandLineToArgvW` and the
/// C runtime parse back).
fn quote_arg(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\n', '\x0b']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// A process created inside a job.
#[derive(Debug)]
pub struct Proc {
    handle: HANDLE,
    /// Process ID.
    pub pid: u32,
}

// SAFETY: a process handle is usable from any thread.
unsafe impl Send for Proc {}

impl Drop for Proc {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and closed once.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Proc {
    /// Waits up to `limit` (forever when `None`); the exit code once it ended.
    #[must_use]
    pub fn wait(&self, limit: Option<Duration>) -> Option<u32> {
        let ms = limit.map_or(u32::MAX, |d| {
            u32::try_from(d.as_millis()).unwrap_or(u32::MAX - 1)
        });
        // SAFETY: valid process handle.
        if unsafe { WaitForSingleObject(self.handle, ms) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: valid handle; `code` lives across the call.
        let ok = unsafe { GetExitCodeProcess(self.handle, &raw mut code) };
        (ok != 0).then_some(code)
    }

    /// The process start identity (creation time), to tell it from a later reuse of its ID.
    #[must_use]
    pub fn start_identity(&self) -> Option<String> {
        creation_time(self.handle)
    }
}

fn creation_time(handle: HANDLE) -> Option<String> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (zero, zero, zero, zero);
    // SAFETY: valid process handle; the four FILETIMEs live across the call.
    let ok = unsafe { GetProcessTimes(handle, &raw mut c, &raw mut e, &raw mut k, &raw mut u) };
    (ok != 0).then(|| {
        format!(
            "win:{}",
            (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime)
        )
    })
}

/// Creates a process directly inside `job` (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), in its own
/// process group; stdout and stderr go to `console` (inherited otherwise). Only the
/// console handle is inherited.
///
/// # Errors
/// The OS error of process creation.
#[allow(clippy::too_many_lines)] // one creation, each step with its SAFETY note
pub fn spawn_in_job(
    job: &Job,
    argv: &[String],
    cwd: Option<&Path>,
    console: Option<&std::fs::File>,
) -> io::Result<Proc> {
    let mut line = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        quote_arg(a, &mut line);
    }
    let mut cmdline: Vec<u16> = wide(std::ffi::OsStr::new(&line));
    let cwd_w = cwd.map(|p| wide(p.as_os_str()));
    let console_handle = console.map(|f| f.as_raw_handle() as HANDLE);
    if let Some(h) = console_handle {
        // SAFETY: a valid file handle owned by `console`, alive across the creation.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let attrs = if console_handle.is_some() { 2 } else { 1 };
    let mut size = 0usize;
    // SAFETY: the first call only reports the required size (null list).
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), attrs, 0, &raw mut size);
    }
    // usize-aligned storage of at least `size` bytes.
    let mut buf = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = buf.as_mut_ptr().cast();
    // SAFETY: `buf` has the size the OS asked for and outlives every use of `list`.
    if unsafe { InitializeProcThreadAttributeList(list, attrs, 0, &raw mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let job_handle = job.handle;
    let inherit = console_handle.unwrap_or(std::ptr::null_mut());
    let result = (|| {
        // SAFETY: the value pointers point at locals that live until CreateProcessW returns.
        unsafe {
            if UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                std::ptr::from_ref(&job_handle).cast::<c_void>(),
                std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            if console_handle.is_some()
                && UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    std::ptr::from_ref(&inherit).cast::<c_void>(),
                    std::mem::size_of::<HANDLE>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: zeroed plain data, then the fields CreateProcessW reads are set.
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb =
            u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
        si.lpAttributeList = list;
        if let Some(h) = console_handle {
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = std::ptr::null_mut();
            si.StartupInfo.hStdOutput = h;
            si.StartupInfo.hStdError = h;
        }
        // SAFETY: zeroed plain data written by CreateProcessW.
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `cmdline` is a mutable NUL-terminated buffer; `cwd_w` NUL-terminated or
        // null; `si` and `pi` live across the call; the environment is inherited.
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                i32::from(console_handle.is_some()),
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_NEW_PROCESS_GROUP
                    | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                cwd_w.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                &raw const si.StartupInfo,
                &raw mut pi,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the thread handle is ours; only the process handle is kept.
        unsafe {
            CloseHandle(pi.hThread);
        }
        Ok(Proc {
            handle: pi.hProcess,
            pid: pi.dwProcessId,
        })
    })();
    // SAFETY: the list was initialized above and is deleted once.
    unsafe {
        DeleteProcThreadAttributeList(list);
    }
    result
}

/// Sends CTRL_BREAK to a process group (best effort: needs a shared console).
pub fn ctrl_break(pid: u32) -> bool {
    // SAFETY: plain call; a failure (no console) is reported, not fatal.
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0 }
}

/// Renames with write-through (the rename is on disk when this returns).
///
/// # Errors
/// The OS error.
pub fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (wide(from.as_os_str()), wide(to.as_os_str()));
    // SAFETY: both buffers are NUL-terminated UTF-16 and live across the call.
    let ok = unsafe {
        MoveFileExW(
            f.as_ptr(),
            t.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The start identity of a running process, or `None` when it is not running.
#[must_use]
pub fn process_identity(pid: u32) -> Option<String> {
    const STILL_ACTIVE: u32 = 259;
    // SAFETY: plain call; a null handle means no such process (or no access).
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut code = 0u32;
    // SAFETY: `h` is a valid process handle; `code` lives across the call.
    let ok = unsafe { GetExitCodeProcess(h, &raw mut code) };
    let id = if ok != 0 && code == STILL_ACTIVE {
        creation_time(h)
    } else {
        None
    };
    // SAFETY: closing the handle we opened.
    unsafe {
        CloseHandle(h);
    }
    id
}

/// Owner-only access: a protected DACL granting full control to the owner (OWNER RIGHTS)
/// and SYSTEM, inherited by everything created inside.
const PRIVATE_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";

/// Owner-only access for a file: a protected DACL granting full control to the owner
/// (OWNER RIGHTS) and SYSTEM.
const PRIVATE_FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";

/// Creates a new file (fails if it exists) that only its owner (and SYSTEM) can access:
/// the DACL is set at creation, never inherited from the directory.
///
/// # Errors
/// The OS error.
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle as _;
    let sddl = wide(std::ffi::OsStr::new(PRIVATE_FILE_SDDL));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let p = wide(path.as_os_str());
    // GENERIC_READ | GENERIC_WRITE.
    let access: u32 = 0x8000_0000 | 0x4000_0000;
    // SAFETY: `p` is NUL-terminated; `sa` and the descriptor live across the call.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            access,
            0,
            &raw const sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let err =
        (h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE).then(io::Error::last_os_error);
    // SAFETY: the descriptor was allocated by the conversion above.
    unsafe {
        LocalFree(sd);
    }
    match err {
        Some(e) => Err(e),
        // SAFETY: a valid handle this function owns, transferred to the File.
        None => Ok(unsafe { std::fs::File::from_raw_handle(h) }),
    }
}

/// Creates a directory that only its owner (and SYSTEM) can access.
///
/// # Errors
/// The OS error (an existing directory is an error: check it with [`check_private`]).
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let sddl = wide(std::ffi::OsStr::new(PRIVATE_SDDL));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let p = wide(path.as_os_str());
    // SAFETY: `p` is NUL-terminated; `sa` and the descriptor live across the call.
    let created = unsafe { CreateDirectoryW(p.as_ptr(), &raw const sa) };
    let err = (created == 0).then(io::Error::last_os_error);
    // SAFETY: the descriptor was allocated by the conversion above.
    unsafe {
        LocalFree(sd);
    }
    err.map_or(Ok(()), Err)
}

/// Checks that a directory's DACL is protected and grants access only to OWNER RIGHTS,
/// SYSTEM, or the directory's owner.
///
/// # Errors
/// An unreadable or broader DACL.
pub fn check_private(path: &Path) -> io::Result<()> {
    let p = wide(path.as_os_str());
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out-pointers live across the call; `sd` is LocalAlloc'd and freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(-1),
        ));
    }
    let result = (|| {
        let mut control = 0u16;
        let mut rev = 0u32;
        // SAFETY: `sd` is valid until freed below.
        if unsafe { GetSecurityDescriptorControl(sd, &raw mut control, &raw mut rev) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
            return Err(io::Error::other(
                "directory access is inherited, not owner-only",
            ));
        }
        let mut allowed = [[0u8; 68]; 2];
        for (i, kind) in [WinCreatorOwnerRightsSid, WinLocalSystemSid]
            .into_iter()
            .enumerate()
        {
            let mut size = 68u32;
            // SAFETY: the buffer is SECURITY_MAX_SID_SIZE (68) bytes.
            if unsafe {
                CreateWellKnownSid(
                    kind,
                    std::ptr::null_mut(),
                    allowed[i].as_mut_ptr().cast(),
                    &raw mut size,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: `dacl` points into `sd`.
        let count = unsafe { (*dacl).AceCount };
        for i in 0..u32::from(count) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: index below the ACE count of a valid ACL.
            if unsafe { GetAce(dacl, i, &raw mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: allow/deny ACEs share this layout; SidStart begins the SID.
            let sid = unsafe {
                std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                    .cast::<c_void>()
            };
            // SAFETY: valid SIDs compared.
            let ok = unsafe {
                EqualSid(sid, allowed[0].as_mut_ptr().cast()) != 0
                    || EqualSid(sid, allowed[1].as_mut_ptr().cast()) != 0
                    || (!owner.is_null() && EqualSid(sid, owner) != 0)
            };
            if !ok {
                return Err(io::Error::other(
                    "directory grants access to other accounts",
                ));
            }
        }
        Ok(())
    })();
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe {
        LocalFree(sd);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::quote_arg;

    #[test]
    fn quoting_follows_the_documented_rules() {
        let q = |a: &str| {
            let mut s = String::new();
            quote_arg(a, &mut s);
            s
        };
        assert_eq!(q("plain"), "plain");
        assert_eq!(q("two words"), "\"two words\"");
        assert_eq!(q(""), "\"\"");
        assert_eq!(q("a\"b"), "\"a\\\"b\"");
        assert_eq!(q("dir\\ x\\"), "\"dir\\ x\\\\\"");
    }
}
