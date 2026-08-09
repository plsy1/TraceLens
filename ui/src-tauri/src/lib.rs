use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{path::BaseDirectory, AppHandle, Manager, RunEvent};

const CORE_ADDRESS: &str = "127.0.0.1:8080";

#[derive(Default)]
struct DesktopCoreState {
    child: Mutex<Option<Child>>,
    launch: Mutex<()>,
    last_error: Mutex<Option<String>>,
}

#[derive(Clone, Serialize)]
struct DesktopStatus {
    core_ready: bool,
    managed_by_desktop: bool,
    api_url: &'static str,
    message: String,
}

fn api_request(method: &str, path: &str) -> std::io::Result<String> {
    let address: SocketAddr = CORE_ADDRESS.parse().expect("static Core address must parse");
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(350))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {CORE_ADDRESS}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn core_is_ready() -> bool {
    api_request("GET", "/api/health")
        .is_ok_and(|response| response.starts_with("HTTP/1.1 200") && response.contains("\"status\":\"ok\""))
}

fn status_for(app: &AppHandle) -> DesktopStatus {
    let state = app.state::<DesktopCoreState>();
    let managed = state.child.lock().is_ok_and(|child| child.is_some());
    let core_ready = core_is_ready();
    let error = state.last_error.lock().ok().and_then(|error| error.clone());
    let message = if core_ready {
        if managed {
            "Core is running and managed by TraceLens Desktop".to_owned()
        } else {
            "Connected to an existing TraceLens Core".to_owned()
        }
    } else {
        error.unwrap_or_else(|| "Core needs administrator authorization".to_owned())
    };
    DesktopStatus {
        core_ready,
        managed_by_desktop: managed,
        api_url: "http://127.0.0.1:8080",
        message,
    }
}

fn bundled_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    if cfg!(debug_assertions) {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repository = manifest
            .parent()
            .and_then(|path| path.parent())
            .ok_or_else(|| "cannot resolve repository root".to_owned())?;
        let core = repository.join("target/debug/tracelens-core");
        let bpf = repository.join("build/bpf/objects");
        if core.is_file() && bpf.is_dir() {
            return Ok((core, bpf));
        }
    }

    let core = app
        .path()
        .resolve("bin/tracelens-core", BaseDirectory::Resource)
        .map_err(|error| format!("cannot resolve bundled Core: {error}"))?;
    let bpf = app
        .path()
        .resolve("bpf/objects", BaseDirectory::Resource)
        .map_err(|error| format!("cannot resolve bundled BPF objects: {error}"))?;
    if !core.is_file() {
        return Err(format!("bundled Core is missing: {}", core.display()));
    }
    if !bpf.is_dir() {
        return Err(format!("bundled BPF objects are missing: {}", bpf.display()));
    }
    Ok((core, bpf))
}

fn launch_core(app: &AppHandle) -> Result<DesktopStatus, String> {
    let state = app.state::<DesktopCoreState>();
    let _launch = state
        .launch
        .lock()
        .map_err(|_| "desktop launch lock is unavailable".to_owned())?;

    if core_is_ready() {
        return Ok(status_for(app));
    }

    let pkexec = PathBuf::from("/usr/bin/pkexec");
    if !pkexec.is_file() {
        return Err("pkexec is required. Install the `pkexec` package and try again.".to_owned());
    }
    let (core_binary, bpf_objects) = bundled_paths(app)?;
    let log_dir = app
        .path()
        .app_log_dir()
        .map_err(|error| format!("cannot resolve log directory: {error}"))?;
    fs::create_dir_all(&log_dir)
        .map_err(|error| format!("cannot create {}: {error}", log_dir.display()))?;
    let log_path = log_dir.join("core.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("cannot open {}: {error}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| format!("cannot clone Core log handle: {error}"))?;

    let mut child = Command::new(pkexec)
        .arg(core_binary)
        .args(["--observe", "--desktop-child", "--api-listen", CORE_ADDRESS])
        .arg("--bpf-object-dir")
        .arg(bpf_objects)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("failed to open administrator authorization: {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if core_is_ready() {
            state
                .child
                .lock()
                .map_err(|_| "desktop Core state is unavailable".to_owned())?
                .replace(child);
            if let Ok(mut error) = state.last_error.lock() {
                *error = None;
            }
            return Ok(status_for(app));
        }
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| format!("cannot inspect Core process: {error}"))?
        {
            let detail = fs::read_to_string(&log_path)
                .ok()
                .and_then(|contents| contents.lines().last().map(str::to_owned))
                .unwrap_or_else(|| "administrator authorization was cancelled".to_owned());
            return Err(format!("Core exited with {exit}: {detail}"));
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err("Core did not become ready within 60 seconds".to_owned())
}

#[tauri::command]
fn desktop_status(app: AppHandle) -> DesktopStatus {
    status_for(&app)
}

#[tauri::command]
async fn ensure_core(app: AppHandle) -> Result<DesktopStatus, String> {
    let task_app = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || launch_core(&task_app))
        .await
        .map_err(|error| format!("Core launch task failed: {error}"))?;
    if let Err(message) = &result {
        let state = app.state::<DesktopCoreState>();
        if let Ok(mut error) = state.last_error.lock() {
            *error = Some(message.clone());
        };
    }
    result
}

fn stop_managed_core(app: &AppHandle) {
    let state = app.state::<DesktopCoreState>();
    let child = state.child.lock().ok().and_then(|mut child| child.take());
    let Some(mut child) = child else {
        return;
    };
    let _ = api_request("POST", "/api/capture/stop");
    let _ = child.kill();
    let _ = child.wait();
}

pub fn run() {
    let app = tauri::Builder::default()
        .manage(DesktopCoreState::default())
        .invoke_handler(tauri::generate_handler![desktop_status, ensure_core])
        .build(tauri::generate_context!())
        .expect("error while building TraceLens desktop application");

    app.run(|app, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            stop_managed_core(app);
        }
    });
}
