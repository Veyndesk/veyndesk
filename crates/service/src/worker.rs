//! The SYSTEM worker in the user's session: runs the host (capture follows the secure
//! desktop, see `veyndesk_host::desktop`), the embedded LAN server, the P2P listener and
//! the pipe the desktop app uses.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::{info, warn};
use veyndesk_host::{
    config::{config_path, one_time_password, Credentials, HostConfig},
    input,
    ipc::{self, Request, ServerState, Settings, WorkerInfo},
    winsec, AuthConfig, HostCommand, UiEvent,
};

/// Same port as the desktop app's embedded server.
const LAN_PORT: u16 = 21118;

struct Worker {
    cfg: Arc<Mutex<HostConfig>>,
    auth: Arc<Mutex<AuthConfig>>,
    otp: Mutex<String>,
    /// Someone is logged on to our session (else: login screen → permanent password only).
    logged_in: AtomicBool,
    user_sid: Mutex<Option<String>>,
    id: Mutex<Option<String>>,
    status: Mutex<String>,
    server_state: Arc<Mutex<ServerState>>,
    cmd: UnboundedSender<HostCommand>,
    rt: tokio::runtime::Handle,
}

impl Worker {
    fn rebuild_auth(&self) {
        let cfg = self.cfg.lock().unwrap().clone();
        let otp = self.otp.lock().unwrap().clone();
        let logged_in = self.logged_in.load(Ordering::SeqCst);
        // Nobody logged on: there is no one to read a one-time password or to click
        // Accept, so only unattended (permanent-password) sessions are allowed.
        let mut a = AuthConfig::build(&cfg, logged_in.then_some(otp.as_str()));
        a.ask_on_one_time = cfg.ask_to_accept;
        *self.auth.lock().unwrap() = a;
    }

    fn info(&self) -> WorkerInfo {
        let c = self.cfg.lock().unwrap();
        WorkerInfo {
            id: self.id.lock().unwrap().clone().or_else(|| c.id.clone()),
            password: self.logged_in.load(Ordering::SeqCst).then(|| self.otp.lock().unwrap().clone()),
            server: c.server.clone(),
            name: c.name.clone(),
            permanent: c.permanent.is_some(),
            ask_to_accept: c.ask_to_accept,
            run_server: c.run_server,
            internet: c.internet,
            team_code: c.team_code.clone(),
            server_state: self.server_state.lock().unwrap().clone(),
            status: self.status.lock().unwrap().clone(),
        }
    }

    fn start_server(&self) {
        let st = self.server_state.clone();
        if matches!(*st.lock().unwrap(), ServerState::Running { .. }) {
            return;
        }
        let new = match std::net::TcpListener::bind(("0.0.0.0", LAN_PORT)) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                let data = config_path().parent().map(|p| p.join("server")).unwrap_or_else(|| "server-data".into());
                let st2 = st.clone();
                self.rt.spawn(async move {
                    let r = match tokio::net::TcpListener::from_std(l) {
                        Ok(l) => veyndesk_server::serve_on(l, data).await,
                        Err(e) => Err(e.into()),
                    };
                    if let Err(e) = r {
                        warn!("embedded server stopped: {e}");
                        *st2.lock().unwrap() = ServerState::Failed { error: e.to_string() };
                    }
                });
                ServerState::Running { lan_url: format!("http://{}:{LAN_PORT}", lan_ip()) }
            }
            Err(e) => ServerState::Failed { error: format!("port {LAN_PORT} is busy: {e}") },
        };
        info!("embedded server: {new:?}");
        *st.lock().unwrap() = new;
    }

    fn handle(&self, req: Request) -> Result<serde_json::Value, String> {
        let ok = |v: serde_json::Value| Ok(v);
        match req {
            Request::GetInfo => ok(serde_json::to_value(self.info()).unwrap()),
            Request::NewPassword => {
                let (pw, _) = one_time_password();
                *self.otp.lock().unwrap() = pw.clone();
                self.rebuild_auth();
                ok(pw.into())
            }
            Request::Respond { sid, accept } => {
                let _ = self.cmd.send(HostCommand::Respond { sid, accept });
                ok(serde_json::Value::Null)
            }
            Request::DisconnectAll => {
                let _ = self.cmd.send(HostCommand::DisconnectAll);
                ok(serde_json::Value::Null)
            }
            Request::Reconnect => {
                let _ = self.cmd.send(HostCommand::Reconnect);
                ok(serde_json::Value::Null)
            }
            Request::Update { settings } => {
                self.update(settings)?;
                ok(serde_json::to_value(self.info()).unwrap())
            }
            Request::SetPermanentPassword { password } => {
                {
                    let mut c = self.cfg.lock().unwrap();
                    match password {
                        Some(p) if p.len() >= 8 => c.permanent = Some(Credentials::from_password(&p)),
                        Some(_) => return Err("Use at least 8 characters.".into()),
                        None => c.permanent = None,
                    }
                    c.save().map_err(|e| e.to_string())?;
                }
                self.rebuild_auth();
                ok(serde_json::Value::Null)
            }
            Request::SetRelay { relay } => {
                veyndesk_host::p2p::set_relay(relay);
                ok(serde_json::Value::Null)
            }
        }
    }

    fn update(&self, s: Settings) -> Result<(), String> {
        // No reconnect here: the app sends `Reconnect` after changing the server, as it
        // does for its own in-process host.
        let start_server = {
            let mut c = self.cfg.lock().unwrap();
            if let Some(v) = s.server {
                c.server = v.trim().to_string();
            }
            if let Some(v) = s.name.filter(|n| !n.trim().is_empty()) {
                c.name = v.trim().to_string();
            }
            if let Some(v) = s.ask_to_accept {
                c.ask_to_accept = v;
            }
            if let Some(v) = s.run_server {
                c.run_server = v;
            }
            if let Some(v) = s.internet {
                c.internet = v;
            }
            if let Some(v) = s.team_code {
                c.team_code = v;
            }
            c.save().map_err(|e| e.to_string())?;
            c.run_server
        };
        if start_server {
            self.start_server();
        }
        self.rebuild_auth();
        Ok(())
    }
}

fn lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

fn viewer_ws(server: &str) -> String {
    let mut c = HostConfig::load_or_default();
    c.server = server.to_string();
    c.ws_url().replace("/ws/host", "/ws/viewer")
}

pub fn run() -> anyhow::Result<()> {
    crate::init_log("worker");
    veyndesk_host::init_platform();
    let session = winsec::current_session();
    info!("Veyndesk worker {} in session {session}", veyndesk_host::VERSION);

    let mut cfg = HostConfig::load_or_default();
    // Same zero-setup default as the desktop app: own small server, reachable P2P by ID.
    if cfg.server.trim().is_empty() {
        cfg.server = format!("http://127.0.0.1:{LAN_PORT}");
        cfg.run_server = true;
    }
    // Not fatal: a locked / unwritable config must not keep the PC unreachable.
    if let Err(e) = cfg.save() {
        warn!("cannot save {}: {e:#}", config_path().display());
    }

    // Ctrl+Alt+Del from a viewer: ask the service (SendSAS needs a service).
    input::set_secure_attention_handler(|| match ipc::request_sas() {
        Ok(()) => true,
        Err(e) => {
            warn!("SendSAS via service failed: {e}");
            false
        }
    });

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ui_tx, mut ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    let user_sid = winsec::session_user_sid(session);
    let w = Arc::new(Worker {
        auth: Arc::new(Mutex::new(AuthConfig::build(&cfg, None))),
        cfg: Arc::new(Mutex::new(cfg)),
        otp: Mutex::new(one_time_password().0),
        logged_in: AtomicBool::new(user_sid.is_some()),
        user_sid: Mutex::new(user_sid),
        id: Mutex::new(None),
        status: Mutex::new("Starting…".into()),
        server_state: Arc::new(Mutex::new(ServerState::Off)),
        cmd: cmd_tx,
        rt: rt.handle().clone(),
    });
    w.rebuild_auth();

    rt.block_on(async move {
        if w.cfg.lock().unwrap().run_server {
            w.start_server();
        }
        let (events, _) = broadcast::channel::<UiEvent>(64);
        let (p2p_tx, p2p_rx) = tokio::sync::watch::channel(None);
        tokio::spawn(veyndesk_host::p2p::serve(p2p_rx));
        tokio::spawn(veyndesk_host::run(
            w.cfg.clone(),
            w.auth.clone(),
            ui_tx,
            cmd_rx,
            veyndesk_host::default_source(),
        ));

        // Host events → status, P2P target, app.
        {
            let (w, events) = (w.clone(), events.clone());
            tokio::spawn(async move {
                while let Some(ev) = ui_rx.recv().await {
                    match &ev {
                        UiEvent::Registered { id } => {
                            *w.id.lock().unwrap() = Some(id.clone());
                            *w.status.lock().unwrap() = "Ready".into();
                            let ws = viewer_ws(&w.cfg.lock().unwrap().server);
                            let _ = p2p_tx.send(Some((id.clone(), ws)));
                        }
                        UiEvent::Connecting { .. } => *w.status.lock().unwrap() = "Connecting…".into(),
                        UiEvent::Disconnected { reason } => *w.status.lock().unwrap() = format!("Offline: {reason}"),
                        _ => {}
                    }
                    let _ = events.send(ev);
                }
            });
        }

        // Login screen ⇄ logged on (same session: the user logs on at the console).
        {
            let w = w.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let sid = tokio::task::spawn_blocking(move || winsec::session_user_sid(session)).await.ok().flatten();
                    let now = sid.is_some();
                    *w.user_sid.lock().unwrap() = sid;
                    if w.logged_in.swap(now, Ordering::SeqCst) != now {
                        info!("session {session}: {}", if now { "user logged on" } else { "login screen (permanent password only)" });
                        w.rebuild_auth();
                    }
                }
            });
        }

        let (w2, w3) = (w.clone(), w.clone());
        ipc::serve_ui(session, move || w2.user_sid.lock().unwrap().clone(), Arc::new(move |req| w3.handle(req)), events).await;
    });
    Ok(())
}
