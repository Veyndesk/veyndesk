//! The LocalSystem service: one SYSTEM worker in the active console session, restarted
//! when it dies or the console session changes; `SendSAS` on request.

use std::{
    collections::HashMap,
    ffi::OsString,
    ptr::null_mut,
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{error, info, warn};
use veyndesk_host::{ipc, winsec::wide};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
        SessionChangeReason,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0},
    Security::{
        Authentication::Identity::SendSAS, DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary,
        TokenSessionId, TOKEN_ALL_ACCESS,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        RemoteDesktop::{
            WTSActive, WTSConnectState, WTSConnected, WTSFreeMemory, WTSGetActiveConsoleSessionId,
            WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE,
        },
        SystemServices::MAXIMUM_ALLOWED,
        Threading::{
            CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, TerminateProcess,
            WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
        },
    },
};

/// No session is attached to the console (e.g. while switching users).
const NO_SESSION: u32 = 0xFFFF_FFFF;
/// Exit codes of a worker that Windows ended because its session is going away (logoff):
/// `DBG_TERMINATE_PROCESS`, `STATUS_CONTROL_C_EXIT`, or a clean exit. Not crashes.
const SESSION_END_CODES: [u32; 3] = [0x4001_0004, 0xC000_013A, 0];
/// How long a logged-off session stays blocked for new workers.
const ENDING_FOR: Duration = Duration::from_secs(15);
/// Only SYSTEM (i.e. our worker) may ask for Ctrl+Alt+Del.
const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)";

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(ipc::SERVICE_NAME, ffi_service_main).map_err(|e| {
        anyhow::anyhow!("{e} — veyndesk-service must be started by the Windows service manager (sc start Veyndesk)")
    })
}

fn service_main(_args: Vec<OsString>) {
    crate::init_log("service");
    if let Err(e) = run_service() {
        error!("service failed: {e:#}");
    }
}

enum Ev {
    Stop,
    SessionChange { reason: SessionChangeReason, session: u32 },
}

fn run_service() -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel::<Ev>();
    let status = service_control_handler::register(ipc::SERVICE_NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(Ev::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(p) => {
            info!("session change: {:?} (session {})", p.reason, p.notification.session_id);
            let _ = tx.send(Ev::SessionChange { reason: p.reason, session: p.notification.session_id });
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let set = |state: ServiceState, accept: ServiceControlAccept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::SESSION_CHANGE,
    )?;
    info!("Veyndesk service {} started", veyndesk_host::VERSION);

    std::thread::Builder::new().name("sas-pipe".into()).spawn(sas_pipe)?;
    supervise(&rx);

    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    info!("Veyndesk service stopped");
    Ok(())
}

struct Worker {
    process: HANDLE,
    /// Kill-on-close job holding only this worker. One job per worker: a job is bound to
    /// the session of its first process, so a shared job can't take workers of other
    /// sessions (`AssignProcessToJobObject` → error 5) and those would outlive the service.
    job: HANDLE,
    session: u32,
    started: Instant,
}

impl Worker {
    fn exited(&self) -> Option<u32> {
        unsafe {
            if WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0 {
                return None;
            }
            let mut code = 0;
            GetExitCodeProcess(self.process, &mut code);
            Some(code)
        }
    }
    fn kill(self) {
        unsafe {
            TerminateProcess(self.process, 0);
            WaitForSingleObject(self.process, 3000);
        }
        self.close();
    }
    /// Closing the job also kills the worker if it's still alive.
    fn close(self) {
        unsafe {
            CloseHandle(self.process);
            if !self.job.is_null() {
                CloseHandle(self.job);
            }
        }
    }
}

/// Keep exactly one worker in the active console session.
fn supervise(rx: &mpsc::Receiver<Ev>) {
    let mut worker: Option<Worker> = None;
    // Crash-loop backoff, per session: a new console session starts right away.
    let mut backoff: Option<(u32, Instant)> = None;
    // Sessions being logged off: never respawn into them. `Some(t)` = forget at `t`.
    let mut ending: HashMap<u32, Option<Instant>> = HashMap::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Ev::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Ok(Ev::SessionChange { reason, session }) => match reason {
                SessionChangeReason::SessionLogoff => {
                    ending.insert(session, Some(Instant::now() + ENDING_FOR));
                }
                SessionChangeReason::SessionLogon => {
                    ending.remove(&session);
                }
                _ => {}
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let now = Instant::now();
        ending.retain(|&s, until| until.is_none_or(|t| now < t) && connect_state(s).is_some());
        let console = unsafe { WTSGetActiveConsoleSessionId() };

        if let Some(w) = &worker {
            if let Some(code) = w.exited() {
                if SESSION_END_CODES.contains(&code) {
                    info!("worker in session {} ended with its session (code {code:#x})", w.session);
                    ending.entry(w.session).or_insert(None);
                } else {
                    warn!("worker in session {} exited with code {code}", w.session);
                    // Crash loop protection: wait longer if it died quickly.
                    let quick = w.started.elapsed() < Duration::from_secs(10);
                    backoff = Some((w.session, now + Duration::from_secs(if quick { 5 } else { 1 })));
                }
                worker.take().unwrap().close();
            } else if console != NO_SESSION && w.session != console {
                // NO_SESSION shows up briefly during fast user switching: keep the worker.
                info!("console session changed {} -> {console}; restarting worker", w.session);
                worker.take().unwrap().kill();
            }
        }

        if worker.is_some() || console == NO_SESSION || ending.contains_key(&console) {
            continue;
        }
        if backoff.is_some_and(|(s, t)| s == console && now < t) {
            continue;
        }
        let state = connect_state(console);
        if !matches!(state, Some(s) if s == WTSActive || s == WTSConnected) {
            continue; // disconnected / being torn down: wait for the next console session
        }
        match spawn_worker(console) {
            Ok(w) => {
                info!("worker started in session {console}");
                worker = Some(w);
            }
            Err(e) => {
                error!("cannot start worker in session {console}: {e:#}");
                backoff = Some((console, now + Duration::from_secs(5)));
            }
        }
    }
    if let Some(w) = worker {
        w.kill();
    }
}

/// `WTSConnectState` of a session (`WTSActive`, `WTSConnected`, …), `None` if it's gone.
fn connect_state(session: u32) -> Option<i32> {
    unsafe {
        let mut buf: windows_sys::core::PWSTR = null_mut();
        let mut len = 0u32;
        if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSConnectState, &mut buf, &mut len) == 0
            || buf.is_null()
        {
            return None;
        }
        let state = *(buf as *const i32);
        WTSFreeMemory(buf.cast());
        Some(state)
    }
}

fn kill_on_close_job() -> HANDLE {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            warn!("CreateJobObjectW failed ({})", GetLastError());
            return job;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        job
    }
}

/// Start `veyndesk-service --worker` as SYSTEM in `session`, on `winsta0\default`:
/// our own (LocalSystem) token, duplicated, with its session id changed.
fn spawn_worker(session: u32) -> anyhow::Result<Worker> {
    let exe = std::env::current_exe()?;
    let mut cmd = wide(format!("\"{}\" --worker", exe.display()));
    let mut desktop = wide(r"winsta0\default");
    unsafe {
        let mut own: HANDLE = null_mut();
        anyhow::ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut own) != 0,
            "OpenProcessToken failed ({})",
            GetLastError()
        );
        let mut token: HANDLE = null_mut();
        let ok = DuplicateTokenEx(own, MAXIMUM_ALLOWED, std::ptr::null(), SecurityImpersonation, TokenPrimary, &mut token);
        CloseHandle(own);
        anyhow::ensure!(ok != 0, "DuplicateTokenEx failed ({})", GetLastError());
        let result = (|| {
            anyhow::ensure!(
                SetTokenInformation(token, TokenSessionId, (&session as *const u32).cast(), 4) != 0,
                "SetTokenInformation(TokenSessionId) failed ({})",
                GetLastError()
            );
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.lpDesktop = desktop.as_mut_ptr();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            anyhow::ensure!(
                CreateProcessAsUserW(
                    token,
                    std::ptr::null(),
                    cmd.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    CREATE_NO_WINDOW,
                    std::ptr::null(),
                    std::ptr::null(),
                    &si,
                    &mut pi,
                ) != 0,
                "CreateProcessAsUserW failed ({})",
                GetLastError()
            );
            CloseHandle(pi.hThread);
            // The worker dies with the service: closing the job (or the service exiting) kills it.
            let mut job = kill_on_close_job();
            if !job.is_null() && AssignProcessToJobObject(job, pi.hProcess) == 0 {
                warn!("AssignProcessToJobObject failed ({}); the worker may outlive the service", GetLastError());
                CloseHandle(job);
                job = null_mut();
            }
            Ok(Worker { process: pi.hProcess, job, session, started: Instant::now() })
        })();
        CloseHandle(token);
        result
    }
}

/// `\\.\pipe\veyndesk-service`: the worker writes `sas`, we raise Ctrl+Alt+Del.
fn sas_pipe() {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return error!("sas pipe runtime: {e}"),
    };
    rt.block_on(ipc::serve_pipe(ipc::SERVICE_PIPE.to_string(), || Some(SERVICE_PIPE_SDDL.to_string()), |pipe| async move {
        let (r, mut w) = tokio::io::split(pipe);
        let mut line = String::new();
        if BufReader::new(r).read_line(&mut line).await.is_err() {
            return;
        }
        let reply = if line.trim() == "sas" {
            // Needs the SoftwareSASGeneration policy (set by the installer), else a no-op.
            unsafe { SendSAS(0) };
            info!("Ctrl+Alt+Del (SendSAS) raised for a viewer");
            "ok\n"
        } else {
            "unknown\n"
        };
        let _ = w.write_all(reply.as_bytes()).await;
    }));
}
