//! Platform supervision: run a command as a supervised process tree with a
//! timeout, and report platform-neutral runner facts.
//!
//! Linux: own process group; timeout → `SIGTERM` to the group, `SIGKILL` after the grace
//! period. Windows: created directly inside a kill-on-close Job Object (no window between
//! creation and membership) in its own process group; timeout → `CTRL_BREAK` (best
//! effort), then job termination after the grace period. Waiting after the forced stop is
//! bounded too: a process that cannot be reaped is reported (`unreaped`), never waited for
//! forever.

#[cfg(windows)]
pub mod windows;

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// How the supervised process ended (maps to `TerminationKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// Exited on its own.
    Exited,
    /// The runner's timeout fired.
    Timeout,
    /// Stopped by a signal or status the runner did not send.
    External,
    /// Ended by a fault (signal, or a Windows exception status).
    Crash,
}

/// Facts of one supervised run.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    /// How it ended.
    pub ended: Ended,
    /// Exit code (when it exited).
    pub exit_code: Option<i32>,
    /// POSIX signal that ended it.
    pub posix_signal: Option<i32>,
    /// Windows status (`0x...`) of an exception or external stop.
    pub windows_status: Option<String>,
    /// Wall seconds (monotonic).
    pub wall_s: f64,
    /// CPU seconds and what they cover.
    pub cpu: Option<(f64, &'static str)>,
    /// Peak memory of the largest process, KiB.
    pub peak_kb: Option<u64>,
    /// The forced stop could not be confirmed within the grace period (or failed): the
    /// tree may still be running.
    pub unreaped: Option<String>,
}

/// What to run.
#[derive(Debug, Clone)]
pub struct Spec<'a> {
    /// Program and arguments.
    pub argv: &'a [String],
    /// Working directory.
    pub cwd: Option<&'a Path>,
    /// Timeout.
    pub timeout: Option<Duration>,
    /// Grace period between the polite stop and the forced one (and to confirm it).
    pub grace: Duration,
    /// Where stdout and stderr go (`None`: inherited): the handle the caller created
    /// exclusively for the attempt (never reopened by path).
    pub console: Option<&'a std::fs::File>,
}

/// Classification of a Windows exit status (public for tests). NTSTATUS values with the
/// severity bits set (warnings 0x8…, errors 0xC…) are exceptions such as an access
/// violation or a breakpoint, except a console control stop (`STATUS_CONTROL_C_EXIT`) and
/// the runner's own kill code.
#[must_use]
pub fn classify_windows_status(
    code: u32,
    runner_kill: u32,
) -> (Ended, Option<i32>, Option<String>) {
    const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;
    let status = || Some(format!("{code:#010x}"));
    if code == runner_kill || code == STATUS_CONTROL_C_EXIT {
        (Ended::External, None, status())
    } else if code >= 0x8000_0000 {
        (Ended::Crash, None, status())
    } else {
        (Ended::Exited, Some(code.cast_signed()), None)
    }
}

/// Runs a command supervised. `on_spawn(pid, start_identity)` is called once the child
/// exists, before the runner waits on it: the journal records the child identity there.
///
/// # Errors
/// The command could not be started (the caller records that as interrupted).
#[cfg(unix)]
pub fn run(spec: &Spec<'_>, on_spawn: &mut dyn FnMut(u32, Option<String>)) -> io::Result<Facts> {
    use nix::sys::resource::{UsageWho, getrusage};
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};

    let (out, err) = match spec.console {
        // The caller's own handle (created exclusively for this attempt).
        Some(f) => (Stdio::from(f.try_clone()?), Stdio::from(f.try_clone()?)),
        None => (Stdio::inherit(), Stdio::inherit()),
    };
    let mut cmd = Command::new(spec.argv.first().map_or("", String::as_str));
    cmd.args(spec.argv.iter().skip(1))
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0);
    if let Some(c) = spec.cwd {
        cmd.current_dir(c);
    }
    let before = getrusage(UsageWho::RUSAGE_CHILDREN).ok();
    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let pid = child.id();
    on_spawn(pid, process_identity(pid));
    let group = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
    let wait = |child: &mut std::process::Child,
                deadline: Option<Instant>|
     -> io::Result<Option<std::process::ExitStatus>> {
        loop {
            if let Some(s) = child.try_wait()? {
                return Ok(Some(s));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let deadline = spec.timeout.map(|t| start + t);
    let mut timed_out = false;
    let mut unreaped = None;
    let status = match wait(&mut child, deadline)? {
        Some(s) => Some(s),
        None => {
            timed_out = true;
            let _ = killpg(group, Signal::SIGTERM);
            match wait(&mut child, Some(Instant::now() + spec.grace))? {
                Some(s) => Some(s),
                None => {
                    if let Err(e) = killpg(group, Signal::SIGKILL) {
                        unreaped = Some(format!("SIGKILL failed: {e}"));
                    }
                    // Bounded: a process in uninterruptible sleep is reported, not awaited.
                    let s = wait(&mut child, Some(Instant::now() + spec.grace))?;
                    if s.is_none() {
                        unreaped.get_or_insert_with(|| "not reaped after SIGKILL".to_string());
                    }
                    s
                }
            }
        }
    };
    // Descendants left in the group are stopped too (daemons that left it are not).
    let _ = killpg(group, Signal::SIGKILL);
    let wall_s = start.elapsed().as_secs_f64();
    let after = getrusage(UsageWho::RUSAGE_CHILDREN).ok();
    let cpu = match (before, after) {
        (Some(b), Some(a)) => {
            let secs = |u: &nix::sys::resource::Usage| {
                let (ut, st) = (u.user_time(), u.system_time());
                #[allow(clippy::cast_precision_loss)] // CPU seconds as a measure
                let s =
                    (ut.tv_sec() + st.tv_sec()) as f64 + (ut.tv_usec() + st.tv_usec()) as f64 / 1e6;
                s
            };
            Some((
                (secs(&a) - secs(&b)).max(0.0),
                "process_and_waited_children",
            ))
        }
        _ => None,
    };
    let peak_kb = after.and_then(|a| u64::try_from(a.max_rss()).ok());
    let (ended, exit_code, posix_signal) = match status {
        None => (Ended::Timeout, None, None),
        Some(s) if timed_out => (Ended::Timeout, s.code(), s.signal()),
        Some(s) => match (s.code(), s.signal()) {
            (Some(c), _) => (Ended::Exited, Some(c), None),
            (None, Some(sig)) => {
                // SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGSYS, SIGTRAP: faults.
                let fault = [11, 7, 6, 4, 8, 31, 5].contains(&sig);
                (
                    if fault { Ended::Crash } else { Ended::External },
                    None,
                    Some(sig),
                )
            }
            _ => (Ended::External, None, None),
        },
    };
    Ok(Facts {
        ended,
        exit_code,
        posix_signal,
        windows_status: None,
        wall_s,
        cpu,
        peak_kb,
        unreaped,
    })
}

/// Runs a command supervised (see the Unix variant).
///
/// # Errors
/// The command could not be started.
#[cfg(windows)]
pub fn run(spec: &Spec<'_>, on_spawn: &mut dyn FnMut(u32, Option<String>)) -> io::Result<Facts> {
    const RUNNER_KILL: u32 = 0xD715_C0DE;
    // The caller's own handle (created exclusively for this attempt).
    let job = windows::Job::new()?;
    let start = Instant::now();
    let child = windows::spawn_in_job(&job, spec.argv, spec.cwd, spec.console)?;
    on_spawn(child.pid, child.start_identity());
    let deadline = spec.timeout.map(|t| start + t);
    let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
    let mut timed_out = false;
    let mut unreaped = None;
    let code = match child.wait(remaining) {
        Some(c) => Some(c),
        None => {
            timed_out = true;
            windows::ctrl_break(child.pid);
            match child.wait(Some(spec.grace)) {
                Some(c) => Some(c),
                None => {
                    if let Some(e) = job.terminate(RUNNER_KILL) {
                        unreaped = Some(format!("job termination failed: {e}"));
                    }
                    // Bounded: termination waiting on I/O completion is reported.
                    let c = child.wait(Some(spec.grace));
                    if c.is_none() {
                        unreaped
                            .get_or_insert_with(|| "not ended after job termination".to_string());
                    }
                    c
                }
            }
        }
    };
    let cpu = job.cpu_seconds().map(|c| (c, "job"));
    let peak_kb = job.peak_process_kb();
    // No descendant outlives the attempt (the job is also killed when it is closed).
    let _ = job.terminate(RUNNER_KILL);
    let wall_s = start.elapsed().as_secs_f64();
    let (ended, exit_code, windows_status) = match code {
        _ if timed_out => (Ended::Timeout, None, None),
        Some(c) => classify_windows_status(c, RUNNER_KILL),
        None => (Ended::External, None, None),
    };
    Ok(Facts {
        ended,
        exit_code,
        posix_signal: None,
        windows_status,
        wall_s,
        cpu,
        peak_kb,
        unreaped,
    })
}

/// The start identity of a running process (`None` when not running): Linux boot ID and
/// start time from `/proc`; Windows creation time.
#[cfg(unix)]
#[must_use]
pub fn process_identity(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesized command name: state is the first, starttime the 20th.
    let after = stat.rsplit_once(')')?.1;
    let mut fields = after.split_whitespace();
    let state = fields.next()?;
    if state == "Z" || state == "X" {
        return None;
    }
    let start = fields.nth(18)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    Some(format!("linux:{}:{start}", boot.trim()))
}

/// The start identity of a running process (`None` when not running).
#[cfg(windows)]
#[must_use]
pub fn process_identity(pid: u32) -> Option<String> {
    windows::process_identity(pid)
}

/// Whether the process that had this ID and start identity is still running (a reused ID
/// is a different process). Without a recorded identity, the ID alone decides.
#[must_use]
pub fn alive(pid: u32, start: Option<&str>) -> bool {
    match (process_identity(pid), start) {
        (Some(now), Some(then)) => now == then,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Creates a directory accessible only to its owner (Unix mode 0700; Windows protected
/// owner-only DACL), failing if it exists.
///
/// # Errors
/// I/O.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        windows::create_private_dir(path)
    }
}

/// Creates a new file (fails if it exists) accessible only to its owner (Unix 0600 set
/// explicitly; Windows protected owner-only DACL set at creation).
///
/// # Errors
/// I/O.
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(f)
    }
    #[cfg(windows)]
    {
        windows::create_private_file(path)
    }
}

/// Writes `data` privately at `path`: a new owner-only sibling written and synced, then
/// renamed over `path` (an existing file, whatever its access, is replaced, never reused).
///
/// # Errors
/// I/O (the sibling is removed).
pub fn write_private_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = path.with_file_name(format!(".{name}.{}.{nonce}.private", std::process::id()));
    let done = create_private_file(&tmp)
        .and_then(|mut f| {
            f.write_all(data)?;
            f.sync_all()
        })
        .and_then(|()| {
            #[cfg(windows)]
            {
                windows::rename_durable(&tmp, path)
            }
            #[cfg(unix)]
            {
                std::fs::rename(&tmp, path)?;
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::File::open(dir)?.sync_all()?;
                }
                Ok(())
            }
        });
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// Checks that an existing directory is accessible only to its owner.
///
/// # Errors
/// Broader access, or I/O.
pub fn check_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::other(format!(
                "{} is accessible to other users (mode {:o})",
                path.display(),
                mode & 0o777
            )));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::check_private(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_replace_a_readable_one() {
        let d = std::env::temp_dir().join(format!("dviscope-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
        let f = d.join("ledger.json");
        // An ordinary file (inherited or default access) is not private.
        std::fs::write(&f, b"old").unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert!(
            check_private(&f).is_err(),
            "an ordinary file is not private"
        );
        write_private_file(&f, b"new").unwrap_or_else(|e| panic!("{e}"));
        assert!(check_private(&f).is_ok(), "{:?}", check_private(&f));
        assert_eq!(std::fs::read(&f).unwrap_or_default(), b"new");
        // A new one is private from creation.
        let g = d.join("case.log");
        write_private_file(&g, b"x").unwrap_or_else(|e| panic!("{e}"));
        assert!(check_private(&g).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn windows_statuses() {
        let kill = 0xD715_C0DE;
        assert_eq!(classify_windows_status(0, kill).0, Ended::Exited);
        assert_eq!(
            classify_windows_status(3, kill),
            (Ended::Exited, Some(3), None)
        );
        assert_eq!(classify_windows_status(0xC000_0005, kill).0, Ended::Crash);
        assert_eq!(classify_windows_status(0x8000_0003, kill).0, Ended::Crash);
        assert_eq!(
            classify_windows_status(0xC000_013A, kill).0,
            Ended::External
        );
        assert_eq!(classify_windows_status(kill, kill).0, Ended::External);
    }
}
