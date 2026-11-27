// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Veyndesk desktop app — one program, like AnyDesk:
//! * shows this PC's ID + password and lets others control it (accept / deny prompt),
//! * opens remote screens of other PCs,
//! * optionally runs a Veyndesk server on this PC so a whole office/LAN needs nothing else.
//!
//! Windows with the Veyndesk service installed: the host runs as SYSTEM in the service's
//! worker (so the UAC prompt and the login screen work); this app is only its UI and talks
//! to it over a named pipe (`veyndesk_host::ipc`). Portable / service-less installs keep
//! running the host in-process.

mod discovery;
mod internet;

use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use veyndesk_host::{
    config::{config_path, one_time_password, Credentials, HostConfig},
    ipc::{Request, ServerState, Settings, WorkerInfo},
    AuthConfig, HostCommand, UiEvent,
};

#[cfg(windows)]
type Svc = veyndesk_host::ipc::UiClient;

/// Never constructed: the service only exists on Windows.
#[cfg(not(windows))]
#[derive(Clone)]
struct Svc;

#[cfg(not(windows))]
impl Svc {
    async fn call(&self, _: Request) -> Result<serde_json::Value, String> {
        Err("no Veyndesk service on this platform".into())
    }
    fn send(&self, _: Request) {}
}

/// Port used when this PC runs the embedded server.
const LAN_PORT: u16 = 21118;

struct AppState {
    cfg: Arc<Mutex<HostConfig>>,
    auth: Arc<Mutex<AuthConfig>>,
    otp: Mutex<String>,
    id: Arc<Mutex<Option<String>>>,
    status: Arc<Mutex<String>>,
    cmd: UnboundedSender<HostCommand>,
    /// `Some(error)` if starting the embedded server failed; `None` while not attempted.
    server_state: Arc<Mutex<ServerState>>,
    net: Arc<internet::Internet>,
    /// `Some` when the Windows service runs the host; `cfg` is then only a mirror of the
    /// worker's settings (the real file is SYSTEM + Administrators only).
    svc: Option<Svc>,
}

/// Every user-facing setting, for pushing the mirror to the worker.
fn settings_of(c: &HostConfig) -> Settings {
    Settings {
        server: Some(c.server.clone()),
        name: Some(c.name.clone()),
        ask_to_accept: Some(c.ask_to_accept),
        run_server: Some(c.run_server),
        internet: Some(c.internet),
        team_code: Some(c.team_code.clone()),
    }
}

/// Save the settings: to our own file, or (service mode) to the worker. Returns the
/// worker's state in service mode.
async fn persist(state: &AppState) -> Result<Option<WorkerInfo>, String> {
    let settings = {
        let c = state.cfg.lock().unwrap();
        if state.svc.is_none() {
            return c.save().map(|_| None).map_err(|e| e.to_string());
        }
        settings_of(&c)
    };
    let svc = state.svc.clone().unwrap();
    let v = svc.call(Request::Update { settings }).await?;
    let w: WorkerInfo = serde_json::from_value(v).map_err(|e| e.to_string())?;
    apply_worker_info(state, &w);
    Ok(Some(w))
}

/// Copy the worker's state into our mirror.
fn apply_worker_info(state: &AppState, w: &WorkerInfo) {
    {
        let mut c = state.cfg.lock().unwrap();
        c.id = w.id.clone();
        c.server = w.server.clone();
        c.name = w.name.clone();
        c.ask_to_accept = w.ask_to_accept;
        c.run_server = w.run_server;
        c.internet = w.internet;
        c.team_code = w.team_code.clone();
    }
    *state.id.lock().unwrap() = w.id.clone();
    *state.otp.lock().unwrap() = w.password.clone().unwrap_or_default();
    *state.server_state.lock().unwrap() = w.server_state.clone();
    *state.status.lock().unwrap() = w.status.clone();
}

fn host_to_request(c: HostCommand) -> Request {
    match c {
        HostCommand::DisconnectAll => Request::DisconnectAll,
        HostCommand::Reconnect => Request::Reconnect,
        HostCommand::Respond { sid, accept } => Request::Respond { sid, accept },
    }
}

#[derive(Serialize)]
struct Info {
    id: Option<String>,
    password: String,
    server: String,
    name: String,
    permanent: bool,
    ask_to_accept: bool,
    run_server: bool,
    server_state: ServerState,
    status: String,
    lan_ip: String,
    internet: bool,
    internet_state: internet::NetState,
    team_code: Option<String>,
    version: &'static str,
}

fn rebuild_auth(state: &AppState) {
    if state.svc.is_some() {
        return; // the worker owns authentication
    }
    let cfg = state.cfg.lock().unwrap().clone();
    let otp = state.otp.lock().unwrap().clone();
    let mut a = AuthConfig::build(&cfg, Some(&otp));
    a.ask_on_one_time = cfg.ask_to_accept;
    *state.auth.lock().unwrap() = a;
}

fn http_base(server: &str) -> String {
    let s = server.trim().trim_end_matches('/');
    let s = s.strip_suffix("/ws/host").unwrap_or(s);
    if let Some(r) = s.strip_prefix("wss://") {
        format!("https://{r}")
    } else if let Some(r) = s.strip_prefix("ws://") {
        format!("http://{r}")
    } else if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    }
}

/// This PC's LAN address (no packets are sent; UDP connect only picks a route).
fn lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

/// Starts the embedded server (idempotent). Returns the state after the attempt.
fn start_embedded_server(server_state: &Arc<Mutex<ServerState>>) -> ServerState {
    if let ServerState::Running { .. } = &*server_state.lock().unwrap() {
        return server_state.lock().unwrap().clone();
    }
    let new_state = match std::net::TcpListener::bind(("0.0.0.0", LAN_PORT)) {
        Ok(listener) => {
            let _ = listener.set_nonblocking(true);
            let data = config_path().parent().map(|p| p.join("server")).unwrap_or_else(|| "server-data".into());
            let st = server_state.clone();
            tauri::async_runtime::spawn(async move {
                let result = match tokio::net::TcpListener::from_std(listener) {
                    Ok(l) => veyndesk_server::serve_on(l, data).await,
                    Err(e) => Err(e.into()),
                };
                if let Err(e) = result {
                    *st.lock().unwrap() = ServerState::Failed { error: e.to_string() };
                }
            });
            ServerState::Running { lan_url: format!("http://{}:{LAN_PORT}", lan_ip()) }
        }
        Err(e) => ServerState::Failed { error: format!("port {LAN_PORT} is busy: {e}") },
    };
    *server_state.lock().unwrap() = new_state.clone();
    new_state
}

// ------------------------------------------------------------------ commands

#[tauri::command]
async fn get_info(state: State<'_, AppState>) -> Result<Info, String> {
    let mut permanent = None;
    if let Some(svc) = state.svc.clone() {
        match svc.call(Request::GetInfo).await.and_then(|v| serde_json::from_value::<WorkerInfo>(v).map_err(|e| e.to_string())) {
            Ok(w) => {
                apply_worker_info(&state, &w);
                permanent = Some(w.permanent);
            }
            Err(e) => *state.status.lock().unwrap() = format!("Offline: {e}"),
        }
    }
    let cfg = state.cfg.lock().unwrap();
    Ok(Info {
        id: state.id.lock().unwrap().clone().or_else(|| cfg.id.clone()),
        password: state.otp.lock().unwrap().clone(),
        server: cfg.server.clone(),
        name: cfg.name.clone(),
        permanent: permanent.unwrap_or(cfg.permanent.is_some()),
        ask_to_accept: cfg.ask_to_accept,
        run_server: cfg.run_server,
        server_state: state.server_state.lock().unwrap().clone(),
        status: state.status.lock().unwrap().clone(),
        lan_ip: lan_ip(),
        internet: cfg.internet,
        internet_state: state.net.state.lock().unwrap().clone(),
        team_code: cfg.team_code.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Server PC: make the built-in server reachable from any network (free Cloudflare tunnel).
#[tauri::command]
async fn enable_internet(state: State<'_, AppState>, enable: bool) -> Result<Option<String>, String> {
    let code = {
        let mut cfg = state.cfg.lock().unwrap();
        cfg.internet = enable;
        if enable {
            cfg.run_server = true;
            if !matches!(*state.server_state.lock().unwrap(), ServerState::Running { .. }) {
                cfg.server = format!("http://127.0.0.1:{LAN_PORT}");
            }
            if cfg.team_code.is_none() {
                cfg.team_code = Some(internet::new_code());
            }
        }
        cfg.team_code.clone()
    };
    // Service mode: the worker starts the embedded server when `run_server` is set.
    let worker = persist(&state).await?;
    if enable {
        let st = match worker {
            Some(w) => w.server_state,
            None => start_embedded_server(&state.server_state),
        };
        if let ServerState::Failed { error } = st {
            return Err(error);
        }
        let _ = state.cmd.send(HostCommand::Reconnect);
        state.net.set_code(code.clone());
        state.net.start(LAN_PORT);
    } else {
        // Keep the tunnel itself: it is also the automatic relay for direct connections.
        state.net.set_code(None);
    }
    Ok(code)
}

/// Other PCs: join the team's server from anywhere using the team code.
#[tauri::command]
async fn join_team(state: State<'_, AppState>, code: String) -> Result<String, String> {
    let code = internet::normalize_code(&code).ok_or("A team code looks like ABCD-2345 (8 letters/digits).")?;
    let c2 = code.clone();
    let url = tauri::async_runtime::spawn_blocking(move || internet::resolve(&c2))
        .await
        .map_err(|e| e.to_string())??;
    {
        let mut cfg = state.cfg.lock().unwrap();
        cfg.team_code = Some(code);
        cfg.server = url.clone();
    }
    persist(&state).await?;
    let _ = state.cmd.send(HostCommand::Reconnect);
    Ok(url)
}

#[tauri::command]
async fn new_password(state: State<'_, AppState>) -> Result<String, String> {
    if let Some(svc) = state.svc.clone() {
        let pw = svc.call(Request::NewPassword).await?.as_str().unwrap_or_default().to_string();
        *state.otp.lock().unwrap() = pw.clone();
        return Ok(pw);
    }
    let (pw, _) = one_time_password();
    *state.otp.lock().unwrap() = pw.clone();
    rebuild_auth(&state);
    Ok(pw)
}

#[tauri::command]
async fn set_server(state: State<'_, AppState>, server: String, name: String) -> Result<(), String> {
    {
        let mut cfg = state.cfg.lock().unwrap();
        cfg.server = server.trim().to_string();
        if !name.trim().is_empty() {
            cfg.name = name.trim().to_string();
        }
    }
    persist(&state).await?;
    let _ = state.cmd.send(HostCommand::Reconnect);
    Ok(())
}

/// Turn this PC into the server for the local network.
#[tauri::command]
async fn enable_lan_server(state: State<'_, AppState>, enable: bool) -> Result<ServerState, String> {
    {
        let mut cfg = state.cfg.lock().unwrap();
        cfg.run_server = enable;
        if enable {
            cfg.server = format!("http://127.0.0.1:{LAN_PORT}");
        }
    }
    let worker = persist(&state).await?;
    if !enable {
        // Keeps running until the app restarts (sessions may depend on it).
        return Ok(state.server_state.lock().unwrap().clone());
    }
    let st = match worker {
        Some(w) => w.server_state,
        None => start_embedded_server(&state.server_state),
    };
    let _ = state.cmd.send(HostCommand::Reconnect);
    Ok(st)
}

#[tauri::command]
async fn set_options(state: State<'_, AppState>, ask_to_accept: bool) -> Result<(), String> {
    state.cfg.lock().unwrap().ask_to_accept = ask_to_accept;
    persist(&state).await?;
    rebuild_auth(&state);
    Ok(())
}

#[tauri::command]
async fn set_permanent_password(state: State<'_, AppState>, password: Option<String>) -> Result<(), String> {
    if let Some(svc) = state.svc.clone() {
        svc.call(Request::SetPermanentPassword { password }).await?;
        return Ok(());
    }
    {
        let mut cfg = state.cfg.lock().unwrap();
        match password {
            Some(p) if p.len() >= 8 => cfg.permanent = Some(Credentials::from_password(&p)),
            Some(_) => return Err("Use at least 8 characters.".into()),
            None => cfg.permanent = None,
        }
        cfg.save().map_err(|e| e.to_string())?;
    }
    rebuild_auth(&state);
    Ok(())
}

#[tauri::command]
fn respond(state: State<'_, AppState>, sid: u32, accept: bool) {
    let _ = state.cmd.send(HostCommand::Respond { sid, accept });
}

#[tauri::command]
fn disconnect_all(state: State<'_, AppState>) {
    let _ = state.cmd.send(HostCommand::DisconnectAll);
}

/// Opens the remote screen of partner `id` in a new window.
///
/// Must be `async`: creating a window from a synchronous command deadlocks on Windows
/// (the window stays white). The viewer page is bundled with the app, so a firewall or
/// wrong address shows a readable error instead of a blank window.
/// LAN servers found by broadcast (for first-run setup).
#[tauri::command]
async fn discover_servers() -> Vec<discovery::Answer> {
    discovery::find_servers().await
}

/// Opens the remote screen of a partner, given an ID or an IP address, in a new window.
///
/// * IP address → asks that PC directly (UDP 21119) for its ID and server.
/// * ID → first asks the LAN who has it (so IDs work even if PCs use different servers),
///   then falls back to the configured server (internet / VPS server).
///
/// Must be `async`: creating a window from a synchronous command deadlocks on Windows.
#[tauri::command]
async fn open_viewer(app: tauri::AppHandle, state: State<'_, AppState>, id: String) -> Result<(), String> {
    let raw = id.trim().to_string();
    let configured = state.cfg.lock().unwrap().server.clone();
    let (server, id) = if raw.contains('.') {
        let host = raw.split(':').next().unwrap_or("").trim();
        let ip: std::net::IpAddr = host.parse().map_err(|_| format!("'{raw}' is not a valid IP address or ID"))?;
        let a = discovery::probe_ip(ip).await.ok_or_else(|| {
            format!("No Veyndesk answered at {ip}. Make sure Veyndesk is open there and allowed in Windows Firewall.")
        })?;
        let id = a.id.ok_or("That PC is not ready yet (no ID). Try again in a few seconds.")?;
        (a.server, id)
    } else {
        let id: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if id.len() < 6 {
            return Err("Enter a remote ID (9 digits) or an IP address".into());
        }
        // Fallback server if a direct connection is impossible: the partner's LAN server,
        // else our team server (a loopback server only knows this PC, so it's no fallback).
        let fallback = match discovery::find_id(&id).await {
            Some(a) => a.server,
            None if !is_loopback(&configured) => http_base(&configured),
            None => String::new(),
        };
        (fallback, id)
    };
    let p2p = !raw.contains('.');
    let server = if server.is_empty() { String::new() } else { http_base(&server) };
    let init = format!(
        "window.__VEYNDESK__ = {};",
        serde_json::json!({ "server": if server.is_empty() { serde_json::Value::Null } else { server.into() }, "id": id, "embedded": true, "p2p": p2p })
    );
    let label = format!("remote-{id}-{}", app.webview_windows().len());
    WebviewWindowBuilder::new(&app, label, WebviewUrl::App("viewer.html".into()))
        .initialization_script(&init)
        .title(format!("Veyndesk — {id}"))
        .inner_size(1280.0, 800.0)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn is_loopback(server: &str) -> bool {
    server.trim().is_empty() || server.contains("127.0.0.1") || server.contains("localhost")
}

fn viewer_ws(server: &str) -> String {
    let mut c = HostConfig::load_or_default();
    c.server = server.to_string();
    c.ws_url().replace("/ws/host", "/ws/viewer")
}

/// Viewer window: deliver its WebRTC offer to partner `id` (via public signaling) and return the answer.
#[tauri::command]
async fn p2p_signal(id: String, sdp: String) -> Result<serde_json::Value, String> {
    let (sdp, relay) = veyndesk_host::p2p::request_answer(&id, sdp).await?;
    Ok(serde_json::json!({ "sdp": sdp, "relay": relay }))
}

fn main() {
    tracing_subscriber::fmt::init();
    veyndesk_host::init_platform();

    #[cfg(windows)]
    let service = veyndesk_host::ipc::service_installed();
    #[cfg(not(windows))]
    let service = false;

    let mut cfg = HostConfig::load_or_default();
    // Zero setup: every PC runs its own small server and is reachable peer-to-peer by ID.
    if cfg.server.trim().is_empty() {
        cfg.server = format!("http://127.0.0.1:{LAN_PORT}");
        cfg.run_server = true;
    }
    if !service {
        let _ = cfg.save();
    }
    let (otp, _) = one_time_password();
    let mut auth = AuthConfig::build(&cfg, Some(&otp));
    auth.ask_on_one_time = cfg.ask_to_accept;
    // Service mode: the worker runs the embedded server.
    let run_server = cfg.run_server && !service;
    let auth = Arc::new(Mutex::new(auth));
    let cfg = Arc::new(Mutex::new(cfg));
    let (cmd_tx, mut cmd_rx) = unbounded_channel();
    let (ui_tx, mut ui_rx) = unbounded_channel::<UiEvent>();
    #[cfg(windows)]
    let svc: Option<Svc> = service.then(|| {
        let ui_tx = ui_tx.clone();
        tauri::async_runtime::block_on(async move {
            veyndesk_host::ipc::UiClient::spawn(veyndesk_host::winsec::current_session(), ui_tx)
        })
    });
    #[cfg(not(windows))]
    let svc: Option<Svc> = None;
    let id = Arc::new(Mutex::new(None));
    let status = Arc::new(Mutex::new("Starting…".to_string()));
    let server_state = Arc::new(Mutex::new(ServerState::Off));
    let lan = Arc::new(Mutex::new(discovery::LocalInfo::default()));

    let net = internet::Internet::new();
    let follow_tx = cmd_tx.clone();
    let net_exit = net.clone();
    let state = AppState {
        cfg: cfg.clone(),
        auth: auth.clone(),
        otp: Mutex::new(otp),
        id: id.clone(),
        status: status.clone(),
        cmd: cmd_tx,
        server_state: server_state.clone(),
        net: net.clone(),
        svc: svc.clone(),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_info,
            new_password,
            set_server,
            enable_lan_server,
            set_options,
            set_permanent_password,
            respond,
            disconnect_all,
            discover_servers,
            p2p_signal,
            enable_internet,
            join_team,
            open_viewer
        ])
        .setup(move |app| {
            if run_server {
                start_embedded_server(&server_state);
            }
            // Server PC: internet tunnel. Other PCs: follow the team's current address.
            {
                let c = cfg.lock().unwrap().clone();
                if c.run_server {
                    // Free relay for when a direct (P2P) connection is impossible.
                    if c.internet {
                        net.set_code(c.team_code.clone());
                    }
                    net.start(LAN_PORT);
                }
                // Tell the P2P listener which public relay partners can fall back to.
                let (cfg4, net4, svc4) = (cfg.clone(), net.clone(), svc.clone());
                let mut last_relay = None;
                std::thread::spawn(move || loop {
                    let server = cfg4.lock().unwrap().server.clone();
                    let relay = if is_loopback(&server) {
                        net4.url()
                    } else if server.starts_with("https://") {
                        Some(http_base(&server))
                    } else {
                        None
                    };
                    match &svc4 {
                        // The worker's P2P listener lives in another process.
                        Some(svc) if last_relay.as_ref() != Some(&relay) => {
                            last_relay = Some(relay.clone());
                            let svc = svc.clone();
                            tauri::async_runtime::spawn(async move { svc.send(Request::SetRelay { relay }) });
                        }
                        Some(_) => {}
                        None => veyndesk_host::p2p::set_relay(relay),
                    }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                });
                let cfg2 = cfg.clone();
                internet::spawn_republisher(net.clone(), move || cfg2.lock().unwrap().team_code.clone());
                let (cfg3, svc3) = (cfg.clone(), svc.clone());
                std::thread::spawn(move || loop {
                    let (code, server, is_server) = {
                        let c = cfg3.lock().unwrap();
                        (c.team_code.clone(), c.server.clone(), c.run_server)
                    };
                    if let (Some(code), false) = (code, is_server) {
                        if let Ok(url) = internet::resolve(&code) {
                            if url != server {
                                let settings = {
                                    let mut c = cfg3.lock().unwrap();
                                    c.server = url;
                                    if svc3.is_none() {
                                        let _ = c.save();
                                    }
                                    settings_of(&c)
                                };
                                if let Some(svc) = svc3.clone() {
                                    // Queued before the reconnect below, so it applies first.
                                    tauri::async_runtime::block_on(async move { svc.send(Request::Update { settings }) });
                                }
                                let _ = follow_tx.send(HostCommand::Reconnect);
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(60));
                });
            }
            // Keep the LAN-discovery answer up to date and serve it.
            {
                let (l2, cfg, id, st) = (lan.clone(), cfg.clone(), id.clone(), server_state.clone());
                tauri::async_runtime::spawn(async move {
                    let lan = l2;
                    loop {
                        {
                            let c = cfg.lock().unwrap();
                            let mut l = lan.lock().unwrap();
                            l.id = id.lock().unwrap().clone().or_else(|| c.id.clone());
                            l.name = c.name.clone();
                            l.server = http_base(&c.server);
                            if c.server.trim().is_empty() {
                                l.server.clear();
                            }
                            l.server_port = matches!(*st.lock().unwrap(), ServerState::Running { .. }).then_some(LAN_PORT);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                });
                tauri::async_runtime::spawn(discovery::responder(lan.clone()));
            }
            let (p2p_tx, p2p_rx) = tokio::sync::watch::channel(None);
            let p2p_cfg = cfg.clone();
            match svc.clone() {
                // Service mode: the worker hosts; forward our commands to it.
                Some(svc) => {
                    drop((p2p_rx, auth, ui_tx));
                    tauri::async_runtime::spawn(async move {
                        while let Some(c) = cmd_rx.recv().await {
                            svc.send(host_to_request(c));
                        }
                    });
                }
                None => {
                    tauri::async_runtime::spawn(veyndesk_host::p2p::serve(p2p_rx));
                    tauri::async_runtime::spawn(veyndesk_host::run(cfg, auth, ui_tx, cmd_rx, veyndesk_host::default_source()));
                }
            }
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while let Some(ev) = ui_rx.recv().await {
                    match &ev {
                        UiEvent::Registered { id: new_id } => {
                            *id.lock().unwrap() = Some(new_id.clone());
                            // Listen for direct (P2P) partners on our ID, bridged to the server we're on.
                            let ws = viewer_ws(&p2p_cfg.lock().unwrap().server);
                            let _ = p2p_tx.send(Some((new_id.clone(), ws)));
                            *status.lock().unwrap() = "Ready".into();
                        }
                        UiEvent::Connecting { .. } => *status.lock().unwrap() = "Connecting…".into(),
                        UiEvent::Disconnected { reason } => *status.lock().unwrap() = format!("Offline: {reason}"),
                        UiEvent::ApprovalRequest { .. } => {
                            // Pop the window to the front so the user sees the prompt.
                            if let Some(w) = handle.get_webview_window("main") {
                                let _ = w.unminimize();
                                let _ = w.show();
                                let _ = w.set_focus();
                                let _ = w.request_user_attention(Some(tauri::UserAttentionType::Critical));
                            }
                        }
                        _ => {}
                    }
                    let _ = handle.emit("host-event", &ev);
                }
            });
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_title(&format!("Veyndesk {}", app.package_info().version));
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while starting Veyndesk")
        .run(move |_, ev| {
            if let tauri::RunEvent::Exit = ev {
                net_exit.stop(); // don't leave cloudflared running
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn http_base() {
        assert_eq!(super::http_base("ws://1.2.3.4:8080"), "http://1.2.3.4:8080");
        assert_eq!(super::http_base("wss://desk.example.com/ws/host"), "https://desk.example.com");
        assert_eq!(super::http_base("desk.local:8080/"), "http://desk.local:8080");
    }
}
