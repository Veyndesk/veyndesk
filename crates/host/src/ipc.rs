//! Local IPC between the Windows service, its SYSTEM worker and the desktop app.
//!
//! * `\\.\pipe\veyndesk-ui-<session>`: served by the worker, only the user logged on to that
//!   session may open it. The desktop app reads the ID / one-time password, answers
//!   Accept/Deny prompts and changes settings through it (it can't read the config file,
//!   which is SYSTEM + Administrators only).
//! * `\\.\pipe\veyndesk-service`: served by the service, SYSTEM only. The worker asks for
//!   the real Ctrl+Alt+Del (`SendSAS`) through it.
//!
//! Wire format: one JSON object per line. Client → worker: [`Envelope`]; worker → client:
//! [`PipeMsg`] (replies and pushed [`UiEvent`]s).

use crate::UiEvent;
use serde::{Deserialize, Serialize};

/// Name of the Windows service (also used by the installer).
pub const SERVICE_NAME: &str = "Veyndesk";
pub const SERVICE_PIPE: &str = r"\\.\pipe\veyndesk-service";

pub fn ui_pipe_name(session: u32) -> String {
    format!(r"\\.\pipe\veyndesk-ui-{session}")
}

/// Embedded server status (shared by the app and the worker).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServerState {
    #[default]
    Off,
    Running { lan_url: String },
    Failed { error: String },
}

/// Settings the app may change. `None` = leave as is.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    pub server: Option<String>,
    pub name: Option<String>,
    pub ask_to_accept: Option<bool>,
    pub run_server: Option<bool>,
    pub internet: Option<bool>,
    /// `Some(None)` clears the team code.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub team_code: Option<Option<String>>,
}

/// A field that is present (even as `null`) is `Some(..)`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "snake_case")]
pub enum Request {
    GetInfo,
    /// New one-time password; replies with it.
    NewPassword,
    Respond { sid: u32, accept: bool },
    DisconnectAll,
    Reconnect,
    Update { settings: Settings },
    /// `None` removes it. Sent in clear over the local, user-only pipe.
    SetPermanentPassword { password: Option<String> },
    /// Public relay for P2P fallbacks (computed by the app from its tunnel / server).
    SetRelay { relay: Option<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub id: u64,
    #[serde(flatten)]
    pub req: Request,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PipeMsg {
    Reply {
        id: u64,
        #[serde(default)]
        result: serde_json::Value,
        #[serde(default)]
        error: Option<String>,
    },
    Event { event: UiEvent },
}

/// What the worker reports to the app (`GetInfo`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkerInfo {
    pub id: Option<String>,
    /// `None` while nobody is logged on (only the permanent password works then).
    pub password: Option<String>,
    pub server: String,
    pub name: String,
    pub permanent: bool,
    pub ask_to_accept: bool,
    pub run_server: bool,
    pub internet: bool,
    pub team_code: Option<String>,
    pub server_state: ServerState,
    pub status: String,
}

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::winsec::{wide, SecurityAttributes};
    use std::{
        collections::HashMap,
        io::{BufRead, BufReader, Write},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader},
        net::windows::named_pipe::{ClientOptions, ServerOptions},
        sync::{broadcast, mpsc, oneshot},
    };
    use tracing::{debug, warn};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    };

    /// Is the Veyndesk service installed on this machine? (Any user may ask the SCM.)
    pub fn service_installed() -> bool {
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return false;
            }
            let name = wide(SERVICE_NAME);
            let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS);
            let found = !svc.is_null();
            if found {
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
            found
        }
    }

    /// Worker → service: raise the real Ctrl+Alt+Del. Blocking; only works for SYSTEM.
    pub fn request_sas() -> anyhow::Result<()> {
        let mut pipe = std::fs::OpenOptions::new().read(true).write(true).open(SERVICE_PIPE)?;
        pipe.write_all(b"sas\n")?;
        let mut line = String::new();
        BufReader::new(pipe).read_line(&mut line)?;
        anyhow::ensure!(line.trim() == "ok", "service answered {line:?}");
        Ok(())
    }

    /// Serve a line-based pipe forever: each connection gets `on_conn(reader lines, writer)`.
    /// `sddl()` is re-evaluated for every new pipe instance (`None` = don't listen right now).
    pub async fn serve_pipe<S, F, Fut>(name: String, sddl: S, on_conn: F)
    where
        S: Fn() -> Option<String>,
        F: Fn(tokio::net::windows::named_pipe::NamedPipeServer) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut first = true;
        loop {
            let Some(sddl) = sddl() else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };
            let server = SecurityAttributes::from_sddl(&sddl).and_then(|mut sa| {
                let mut opts = ServerOptions::new();
                opts.first_pipe_instance(first).reject_remote_clients(true);
                // SAFETY: `sa` outlives the call.
                Ok(unsafe { opts.create_with_security_attributes_raw(&name, sa.as_ptr())? })
            });
            let server = match server {
                Ok(s) => s,
                Err(e) => {
                    warn!("cannot create pipe {name}: {e}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            first = false;
            if let Err(e) = server.connect().await {
                debug!("pipe {name}: connect failed: {e}");
                continue;
            }
            tokio::spawn(on_conn(server));
        }
    }

    /// Worker side of the UI pipe. `handle` answers requests; `events` is pushed to every client.
    pub async fn serve_ui<H>(session: u32, user_sid: impl Fn() -> Option<String>, handle: Arc<H>, events: broadcast::Sender<UiEvent>)
    where
        H: Fn(Request) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    {
        serve_pipe(
            ui_pipe_name(session),
            // SYSTEM and the logged-on user of this session only.
            move || user_sid().map(|sid| format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{sid})")),
            move |pipe| {
                let handle = handle.clone();
                let mut ev = events.subscribe();
                async move {
                    let (r, mut w) = tokio::io::split(pipe);
                    let mut lines = TokioBufReader::new(r).lines();
                    loop {
                        let out = tokio::select! {
                            l = lines.next_line() => match l {
                                Ok(Some(l)) => match serde_json::from_str::<Envelope>(&l) {
                                    Ok(env) => {
                                        let h = handle.clone();
                                        let r = tokio::task::spawn_blocking(move || h(env.req)).await
                                            .unwrap_or_else(|e| Err(e.to_string()));
                                        let (result, error) = match r { Ok(v) => (v, None), Err(e) => (serde_json::Value::Null, Some(e)) };
                                        PipeMsg::Reply { id: env.id, result, error }
                                    }
                                    Err(e) => { warn!("bad UI request: {e}"); continue; }
                                },
                                _ => return,
                            },
                            e = ev.recv() => match e {
                                Ok(event) => PipeMsg::Event { event },
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => return,
                            },
                        };
                        let mut line = serde_json::to_string(&out).unwrap();
                        line.push('\n');
                        if w.write_all(line.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                }
            },
        )
        .await
    }

    type Call = (Request, oneshot::Sender<Result<serde_json::Value, String>>);

    /// App side of the UI pipe. Reconnects by itself; worker events go to `events`.
    #[derive(Clone)]
    pub struct UiClient {
        tx: mpsc::UnboundedSender<Call>,
    }

    impl UiClient {
        /// Must be called inside a Tokio runtime.
        pub fn spawn(session: u32, events: mpsc::UnboundedSender<UiEvent>) -> Self {
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(client_loop(ui_pipe_name(session), rx, events));
            Self { tx }
        }

        pub async fn call(&self, req: Request) -> Result<serde_json::Value, String> {
            let (tx, rx) = oneshot::channel();
            self.tx.send((req, tx)).map_err(|_| "IPC closed".to_string())?;
            rx.await.map_err(|_| "Veyndesk service is not answering".to_string())?
        }

        /// Fire and forget (errors are logged). Queued synchronously, so requests sent one
        /// after another reach the worker in that order.
        pub fn send(&self, req: Request) {
            let (tx, rx) = oneshot::channel();
            if self.tx.send((req, tx)).is_err() {
                return;
            }
            tokio::spawn(async move {
                if let Ok(Err(e)) = rx.await {
                    warn!("service request failed: {e}");
                }
            });
        }
    }

    async fn client_loop(name: String, mut calls: mpsc::UnboundedReceiver<Call>, events: mpsc::UnboundedSender<UiEvent>) {
        let mut announced = false;
        loop {
            let pipe = match ClientOptions::new().open(&name) {
                Ok(p) => p,
                Err(e) => {
                    if !announced {
                        announced = true;
                        warn!("cannot open {name}: {e}");
                        let _ = events.send(UiEvent::Disconnected { reason: "Waiting for the Veyndesk service…".into() });
                    }
                    // Fail calls made while the worker is unreachable instead of hanging.
                    let wait = tokio::time::sleep(Duration::from_millis(500));
                    tokio::pin!(wait);
                    loop {
                        tokio::select! {
                            _ = &mut wait => break,
                            c = calls.recv() => match c {
                                Some((_, reply)) => { let _ = reply.send(Err("Veyndesk service is not running".into())); }
                                None => return,
                            },
                        }
                    }
                    continue;
                }
            };
            announced = false;
            let (r, mut w) = tokio::io::split(pipe);
            let mut lines = TokioBufReader::new(r).lines();
            let mut pending: HashMap<u64, oneshot::Sender<Result<serde_json::Value, String>>> = HashMap::new();
            let mut next_id = 0u64;
            // id 0: initial state, so the UI shows the ID even if it registered long ago.
            let hello = format!("{}\n", serde_json::to_string(&Envelope { id: 0, req: Request::GetInfo }).unwrap());
            let _ = w.write_all(hello.as_bytes()).await;
            loop {
                tokio::select! {
                    c = calls.recv() => {
                        let Some((req, reply)) = c else { return };
                        next_id += 1;
                        let line = format!("{}\n", serde_json::to_string(&Envelope { id: next_id, req }).unwrap());
                        if w.write_all(line.as_bytes()).await.is_err() {
                            let _ = reply.send(Err("Veyndesk service disconnected".into()));
                            break;
                        }
                        pending.insert(next_id, reply);
                    }
                    l = lines.next_line() => {
                        let Ok(Some(l)) = l else { break };
                        match serde_json::from_str::<PipeMsg>(&l) {
                            Ok(PipeMsg::Event { event }) => { let _ = events.send(event); }
                            Ok(PipeMsg::Reply { id: 0, result, .. }) => {
                                if let Ok(WorkerInfo { id: Some(id), .. }) = serde_json::from_value(result) {
                                    let _ = events.send(UiEvent::Registered { id });
                                }
                            }
                            Ok(PipeMsg::Reply { id, result, error }) => {
                                if let Some(tx) = pending.remove(&id) {
                                    let _ = tx.send(match error { Some(e) => Err(e), None => Ok(result) });
                                }
                            }
                            Err(e) => warn!("bad message from service: {e}"),
                        }
                    }
                }
            }
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err("Veyndesk service disconnected".into()));
            }
            let _ = events.send(UiEvent::Disconnected { reason: "Lost connection to the Veyndesk service".into() });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let env = Envelope { id: 7, req: Request::Respond { sid: 3, accept: true } };
        let s = serde_json::to_string(&env).unwrap();
        assert_eq!(s, r#"{"id":7,"req":"respond","sid":3,"accept":true}"#);
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.req, Request::Respond { sid: 3, accept: true }));

        let up = Envelope { id: 1, req: Request::Update { settings: Settings { team_code: Some(None), ..Default::default() } } };
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&up).unwrap()).unwrap();
        let Request::Update { settings } = back.req else { panic!() };
        assert_eq!(settings.team_code, Some(None));

        let ev = PipeMsg::Event { event: UiEvent::ApprovalRequest { sid: 1, ip: "1.2.3.4".into() } };
        let back: PipeMsg = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert!(matches!(back, PipeMsg::Event { event: UiEvent::ApprovalRequest { sid: 1, .. } }));
    }
}
