//! `veyndesk-service` — Windows service that makes the host work on the UAC prompt and
//! the lock / login screen (the RustDesk model):
//!
//! * `veyndesk-service --service` (what the SCM runs, as LocalSystem): follows the active
//!   console session and keeps one worker running in it; raises Ctrl+Alt+Del (`SendSAS`)
//!   when the worker asks.
//! * `veyndesk-service --worker` (started by the service, as SYSTEM in the user's session):
//!   the actual host — capture, input, embedded server, P2P — plus the pipe the desktop app
//!   talks to.
//!
//! Installed and removed by the Windows installer (`desktop/src-tauri/windows/hooks.nsh`).

#[cfg(windows)]
mod service;
#[cfg(windows)]
mod worker;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--worker") => {
            // stderr goes nowhere for a worker: put failures in worker.log.
            let r = worker::run();
            if let Err(e) = &r {
                tracing::error!("worker failed: {e:#}");
            }
            r
        }
        Some("--service") | None => service::run(),
        // Admin tools (elevated prompt): edit the machine config the service uses.
        Some("--set-password") => {
            let pw = args.get(1).ok_or_else(|| anyhow::anyhow!("usage: veyndesk-service --set-password <password>"))?;
            anyhow::ensure!(pw.len() >= 8, "use at least 8 characters for a permanent password");
            let mut cfg = machine_config()?;
            cfg.permanent = Some(veyndesk_host::config::Credentials::from_password(pw));
            cfg.save()?;
            println!("Permanent password saved. Restart the service: sc stop Veyndesk && sc start Veyndesk");
            Ok(())
        }
        Some("--show-id") => {
            let cfg = machine_config()?;
            println!("ID: {}", cfg.id.as_deref().unwrap_or("(not registered yet)"));
            println!("Server: {}", cfg.server);
            println!("Permanent password: {}", if cfg.permanent.is_some() { "set" } else { "not set" });
            println!("Config: {}", veyndesk_host::config::config_path().display());
            Ok(())
        }
        Some(other) => anyhow::bail!(
            "unknown argument {other:?}; usage: veyndesk-service [--service | --worker | --set-password <pw> | --show-id]"
        ),
    }
}

#[cfg(windows)]
fn machine_config() -> anyhow::Result<veyndesk_host::config::HostConfig> {
    veyndesk_host::config::use_machine_config();
    veyndesk_host::config::secure_machine_dir()
        .map_err(|e| anyhow::anyhow!("{e} (run from an elevated / administrator prompt)"))?;
    Ok(veyndesk_host::config::HostConfig::load_or_default())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("veyndesk-service only runs on Windows; use veyndesk-host instead")
}

/// Log to `%ProgramData%\Veyndesk\logs\<name>.log` (services have no console).
#[cfg(windows)]
fn init_log(name: &str) {
    use veyndesk_host::config;
    veyndesk_host::config::use_machine_config();
    if let Err(e) = config::secure_machine_dir() {
        eprintln!("cannot secure {}: {e}", config::machine_dir().display());
    }
    let dir = config::machine_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{name}.log"));
    // Keep it small: start over once it passes 5 MB.
    let truncate = std::fs::metadata(&path).map(|m| m.len() > 5 << 20).unwrap_or(false);
    let file = std::fs::OpenOptions::new().create(true).append(!truncate).write(true).truncate(truncate).open(&path);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "veyndesk_service=info,veyndesk_host=info,veyndesk_server=info".into());
    match file {
        Ok(f) => tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(std::sync::Mutex::new(f)).init(),
        Err(_) => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
    // Panics (any thread) would otherwise only reach stderr, which nobody sees here.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let bt = std::backtrace::Backtrace::force_capture();
        tracing::error!("panic in thread {:?}: {info}\n{bt}", thread.name().unwrap_or("?"));
        default_hook(info);
    }));
    veyndesk_server::hide_admin_token_in_logs();
}
