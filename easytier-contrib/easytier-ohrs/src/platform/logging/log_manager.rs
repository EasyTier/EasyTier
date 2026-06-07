use napi_derive_ohos::napi;
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_DIR_NAME: &str = "easytier-logs";
const LOG_FILE_PREFIX: &str = "easytier-";
const LOG_FILE_SUFFIX: &str = ".log";
const MAX_LOG_FILES: usize = 10;
const MAX_MEMORY_LINES: usize = 500;

#[derive(Clone)]
struct LogOptions {
    core_log: bool,
    debug_log: bool,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self {
            core_log: false,
            debug_log: false,
        }
    }
}

#[derive(Default)]
struct LogManagerState {
    log_dir: Option<PathBuf>,
    active_file: Option<PathBuf>,
    lines: VecDeque<String>,
    options: LogOptions,
}

static LOG_MANAGER: Lazy<Mutex<LogManagerState>> =
    Lazy::new(|| Mutex::new(LogManagerState::default()));
static CORE_LOG_ENABLED: AtomicBool = AtomicBool::new(false);
static DEBUG_LOG_ENABLED: AtomicBool = AtomicBool::new(false);

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn sanitize_name(raw: &str) -> String {
    let value = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if value.is_empty() {
        "process".to_string()
    } else {
        value
    }
}

fn log_dir(root_dir: &str) -> PathBuf {
    Path::new(root_dir).join(LOG_DIR_NAME)
}

fn is_log_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with(LOG_FILE_PREFIX) && name.ends_with(LOG_FILE_SUFFIX))
        .unwrap_or(false)
}

fn sorted_log_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .filter(|path| is_log_file(path))
        .collect::<Vec<_>>();
    files.sort_by(|left, right| {
        left.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .cmp(
                right
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            )
    });
    files
}

fn cleanup_old_logs(dir: &Path) {
    let files = sorted_log_files(dir);
    let overflow = files.len().saturating_sub(MAX_LOG_FILES);
    for path in files.into_iter().take(overflow) {
        let _ = fs::remove_file(path);
    }
}

fn push_memory_line(state: &mut LogManagerState, line: String) {
    state.lines.push_back(line);
    while state.lines.len() > MAX_MEMORY_LINES {
        state.lines.pop_front();
    }
}

fn append_log_file(path: &Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}", line);
    }
}

fn should_record_debug(level: i32) -> bool {
    level <= 3
}

fn format_line(level: i32, target: &str, message: &str) -> String {
    format!("{}[{}] {}", level, target, message.replace('\n', "\\n"))
}

pub(crate) fn configure(core_log: bool, debug_log: bool) {
    CORE_LOG_ENABLED.store(core_log, Ordering::Relaxed);
    DEBUG_LOG_ENABLED.store(debug_log, Ordering::Relaxed);
    if let Ok(mut guard) = LOG_MANAGER.lock() {
        guard.options.core_log = core_log;
        guard.options.debug_log = debug_log;
    }
}

pub(crate) fn app_log_enabled(level: i32) -> bool {
    !should_record_debug(level) || DEBUG_LOG_ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn core_log_enabled(level: i32) -> bool {
    CORE_LOG_ENABLED.load(Ordering::Relaxed) && app_log_enabled(level)
}

pub(crate) fn record_app_log(level: i32, target: &str, message: &str) {
    if !app_log_enabled(level) {
        return;
    }
    if let Ok(mut guard) = LOG_MANAGER.lock() {
        let line = format_line(level, target, message);
        if let Some(path) = guard.active_file.as_ref() {
            append_log_file(path, &line);
        }
        push_memory_line(&mut guard, line);
    }
}

pub(crate) fn record_core_log(level: i32, target: &str, message: &str) {
    if !core_log_enabled(level) {
        return;
    }
    if let Ok(mut guard) = LOG_MANAGER.lock() {
        let line = format_line(level, target, message);
        if let Some(path) = guard.active_file.as_ref() {
            append_log_file(path, &line);
        }
        push_memory_line(&mut guard, line);
    }
}

#[napi]
pub fn init_log_manager(root_dir: String, process_name: String) -> bool {
    let dir = log_dir(&root_dir);
    if fs::create_dir_all(&dir).is_err() {
        return false;
    }
    if LOG_MANAGER
        .lock()
        .map(|guard| guard.active_file.is_some())
        .unwrap_or(false)
    {
        cleanup_old_logs(&dir);
        return true;
    }

    let active_file = dir.join(format!(
        "{}{}-{}-{}{}",
        LOG_FILE_PREFIX,
        now_millis(),
        std::process::id(),
        sanitize_name(&process_name),
        LOG_FILE_SUFFIX
    ));
    if OpenOptions::new()
        .create(true)
        .append(true)
        .open(&active_file)
        .is_err()
    {
        return false;
    }

    if let Ok(mut guard) = LOG_MANAGER.lock() {
        guard.log_dir = Some(dir.clone());
        guard.active_file = Some(active_file);
        guard.lines.clear();
    }
    cleanup_old_logs(&dir);
    true
}

#[napi]
pub fn configure_log_manager(core_log: bool, debug_log: bool) {
    configure(core_log, debug_log);
}

#[napi]
pub fn write_app_log(level: i32, target: String, message: String) {
    record_app_log(level, &target, &message);
}

#[napi]
pub fn drain_log_lines() -> Vec<String> {
    LOG_MANAGER
        .lock()
        .map(|mut guard| guard.lines.drain(..).collect())
        .unwrap_or_default()
}

#[napi]
pub fn export_log_archive(target_path: String) -> bool {
    let log_dir = LOG_MANAGER
        .lock()
        .ok()
        .and_then(|guard| guard.log_dir.clone());
    let Some(log_dir) = log_dir else {
        return false;
    };

    let files = sorted_log_files(&log_dir);
    let mut output = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&target_path)
    {
        Ok(file) => file,
        Err(_) => return false,
    };

    for path in files {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown.log");
        let _ = writeln!(output, "===== {} =====", name);
        if let Ok(content) = fs::read_to_string(&path) {
            let _ = writeln!(output, "{}", content);
        }
    }
    true
}
