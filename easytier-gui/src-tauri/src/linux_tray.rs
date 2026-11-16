//! Keep AppIndicator on the desktop user's session bus while the GUI remains elevated.
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    time::Duration,
};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};

use super::UserTrayUpdate;

const CONTROL_ENV: &str = "EASYTIER_GUI_USER_TRAY";
const CONTROL_VALUE: &str = "stdio-v1";
const TRAY_ID: &str = "easytier-user-session";
// Other stdout output is forwarded rather than interpreted as a tray update.
const EVENT_PREFIX: &str = "EASYTIER_GUI_TRAY_EVENT:";

#[derive(Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum GuiEvent {
    Ready,
    Update { update: UserTrayUpdate },
}

enum ControlRequest {
    Show,
    Toggle,
    Quit,
    Ready,
}

struct TrayControl(Sender<ControlRequest>);

impl TrayControl {
    fn send(&self, request: ControlRequest) -> anyhow::Result<()> {
        self.0
            .send(request)
            .map_err(|_| anyhow!("GUI control pipe is closed"))
    }
}

struct TrayMenu {
    show: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
}

pub(super) fn is_controlled() -> bool {
    std::env::var_os(CONTROL_ENV).as_deref() == Some(std::ffi::OsStr::new(CONTROL_VALUE))
}

fn notify(event: GuiEvent) -> anyhow::Result<()> {
    // Lock stdout for the whole frame so concurrent Rust logging cannot split it.
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{EVENT_PREFIX}{}", serde_json::to_string(&event)?)?;
    stdout.flush()?;
    Ok(())
}

pub(super) fn update(update: UserTrayUpdate) -> anyhow::Result<()> {
    anyhow::ensure!(is_controlled(), "No user-session tray is connected");
    notify(GuiEvent::Update { update })
}

fn show_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        window.unminimize()?;
        window.set_focus()?;
    }
    Ok(())
}

fn toggle_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main")
        && window.is_visible()?
        && !window.is_minimized()?
    {
        window.hide()
    } else {
        show_window(app)
    }
}

/// The inherited pipe accepts window commands only, never commands to execute.
pub(super) fn listen(app: AppHandle) -> anyhow::Result<()> {
    notify(GuiEvent::Ready)?;
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let result = match line.as_deref() {
                Ok("show") => show_window(&app),
                Ok("toggle") => toggle_window(&app),
                Ok("quit") | Err(_) => break,
                _ => continue,
            };
            if let Err(error) = result {
                eprintln!("Failed to update EasyTier window: {error}");
            }
        }
        // The user-session owner exited or the pipe closed.
        app.exit(0);
    });
    Ok(())
}

fn apply_event(app: &AppHandle, event: GuiEvent) -> anyhow::Result<()> {
    match event {
        GuiEvent::Ready => {
            app.state::<TrayControl>().send(ControlRequest::Ready)?;
            app.state::<TrayMenu>().show.set_enabled(true)?;
        }
        GuiEvent::Update { update } => match update {
            UserTrayUpdate::Menu { show, quit } => {
                let menu = app.state::<TrayMenu>();
                menu.show.set_text(show)?;
                menu.quit.set_text(quit)?;
            }
            UserTrayUpdate::RunState { running } => {
                let bytes = if running {
                    include_bytes!("../icons/icon-inactive.ico").as_slice()
                } else {
                    include_bytes!("../icons/icon.ico").as_slice()
                };
                let tray = app
                    .tray_by_id(TRAY_ID)
                    .context("User-session tray is missing")?;
                tray.set_icon(Some(tauri::image::Image::from_bytes(bytes)?))?;
            }
            UserTrayUpdate::Tooltip { tooltip } => {
                let tray = app
                    .tray_by_id(TRAY_ID)
                    .context("User-session tray is missing")?;
                tray.set_tooltip(Some(&tooltip))?;
                tray.set_title(Some(&tooltip))?;
            }
        },
    }
    Ok(())
}

fn read_events(stdout: ChildStdout, app: AppHandle) {
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("Failed to read EasyTier GUI output: {error}");
                break;
            }
        }
        if let Some(payload) = line.strip_prefix(EVENT_PREFIX.as_bytes()) {
            let result = serde_json::from_slice(payload)
                .map_err(anyhow::Error::from)
                .and_then(|event| apply_event(&app, event));
            if let Err(error) = result {
                eprintln!("Failed to update EasyTier tray: {error:#}");
            }
        } else {
            // Preserve diagnostic output, including a final line without a newline.
            let _ = std::io::stdout().lock().write_all(&line);
        }
    }
}

struct GuiProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    ready: bool,
    show_requested: bool,
    exit_code: Option<i32>,
}

impl GuiProcess {
    fn write(&mut self, command: &str) -> anyhow::Result<()> {
        let stdin = self.stdin.as_mut().context("GUI control pipe is closed")?;
        writeln!(stdin, "{command}")?;
        Ok(())
    }

    fn quit(&mut self, exit_code: i32) {
        self.exit_code = Some(exit_code);
        // EOF also shuts down a GUI that is still initializing or cannot accept a command.
        self.stdin.take();
        if !self.ready
            && let Err(error) = self.child.kill()
            && error.kind() != std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Failed to cancel EasyTier authentication: {error}");
        }
        // PermissionDenied can mean pkexec has already switched to root. In that
        // race, the GUI will observe EOF as soon as its control listener starts.
    }

    fn handle(&mut self, request: ControlRequest) -> anyhow::Result<()> {
        if self.exit_code.is_some() {
            return Ok(());
        }
        match request {
            ControlRequest::Quit => self.quit(0),
            ControlRequest::Show if !self.ready => self.show_requested = true,
            ControlRequest::Show => self.write("show")?,
            ControlRequest::Toggle if self.ready => self.write("toggle")?,
            ControlRequest::Toggle => {}
            ControlRequest::Ready => {
                self.ready = true;
                if self.show_requested {
                    self.show_requested = false;
                    self.write("show")?;
                }
            }
        }
        Ok(())
    }
}

fn supervise(mut gui: GuiProcess, requests: Receiver<ControlRequest>, app: AppHandle) {
    loop {
        match gui.child.try_wait() {
            Ok(Some(status)) => {
                app.exit(gui.exit_code.unwrap_or_else(|| status.code().unwrap_or(1)));
                return;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("Failed to wait for EasyTier GUI: {error}");
                gui.quit(1);
                app.exit(1);
                return;
            }
        }
        match requests.recv_timeout(Duration::from_millis(100)) {
            Ok(request) => {
                if let Err(error) = gui.handle(request) {
                    eprintln!("Failed to control EasyTier: {error:#}");
                    gui.quit(1);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                gui.quit(0);
                let _ = gui.child.wait();
                app.exit(0);
                return;
            }
        }
    }
}

pub(super) fn run() -> std::process::ExitCode {
    match run_inner() {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("Failed to start EasyTier user-session tray: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_inner() -> anyhow::Result<i32> {
    let mut context = tauri::generate_context!();
    // This process only hosts a tray; the elevated child owns the webview.
    context.config_mut().app.windows.clear();
    let (sender, requests) = mpsc::channel();
    let app = tauri::Builder::default()
        .manage(TrayControl(sender))
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Err(error) = app.state::<TrayControl>().send(ControlRequest::Show) {
                eprintln!("Failed to show EasyTier: {error:#}");
            }
        }))
        .build(context)?;

    // Initialize before entering the event loop so failures return through run().
    let show = MenuItem::with_id(&app, "show", "Show / Hide", false, None::<&str>)?;
    let quit = MenuItem::with_id(&app, "quit", "Exit", true, None::<&str>)?;
    let menu = Menu::with_items(&app, &[&show, &quit])?;
    app.manage(TrayMenu { show, quit });
    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .on_menu_event(|app, event| {
            let request = match event.id().as_ref() {
                "show" => ControlRequest::Toggle,
                "quit" => ControlRequest::Quit,
                _ => return,
            };
            if let Err(error) = app.state::<TrayControl>().send(request) {
                eprintln!("Failed to control EasyTier: {error:#}");
            }
        })
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../icons/icon.png"
        ))?)
        .build(&app)?;

    let mut command = Command::new(super::get_exe_path());
    command.env(CONTROL_ENV, CONTROL_VALUE);
    let mut child = super::elevate::Command::new(command)
        .elevated_command()?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdin = child.stdin.take().context("Missing GUI control pipe")?;
    let stdout = child
        .stdout
        .take()
        .context("Missing GUI notification pipe")?;
    let handle = app.handle().clone();
    std::thread::spawn(move || read_events(stdout, handle));
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        supervise(
            GuiProcess {
                child,
                stdin: Some(stdin),
                ready: false,
                show_requested: false,
                exit_code: None,
            },
            requests,
            handle,
        );
    });

    Ok(app.run_return(|_, _| {}))
}
