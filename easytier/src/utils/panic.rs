use crate::common::log;
use indoc::formatdoc;
use std::fs::OpenOptions;
use std::str::FromStr;
use std::{backtrace, io::Write};

thread_local! {
    static PANIC_COUNT : std::cell::RefCell<u32> = const { std::cell::RefCell::new(0) };
}

pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|info| {
        let mut stderr = std::io::stderr();
        let sep = format!("{}\n", "=======".repeat(10));
        let _ = stderr.write_all(format!("{sep}{}\n{sep}", "!PANIC!".repeat(10)).as_bytes());

        PANIC_COUNT.with(|c| {
            let mut count = c.borrow_mut();
            *count += 1;
        });
        let panic_count = PANIC_COUNT.with(|c| *c.borrow());
        if panic_count > 1 {
            log::error!("panic happened more than once, exit immediately");
            std::process::exit(1);
        }

        let payload = info.payload();
        let payload_str: Option<&str> = if let Some(s) = payload.downcast_ref::<&str>() {
            Some(s)
        } else if let Some(s) = payload.downcast_ref::<String>() {
            Some(s)
        } else {
            None
        };
        let payload_str = payload_str.unwrap_or("<unknown panic info>");
        // The current implementation always returns `Some`.
        let location = info.location().unwrap();
        let thread = std::thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");

        let tmp_path = std::env::temp_dir().join("easytier-panic.log");
        let candidate_path = [
            std::path::PathBuf::from_str("easytier-panic.log").ok(),
            Some(tmp_path),
        ];
        let mut file = None;
        let mut file_path = None;
        for path in candidate_path.iter().filter_map(|p| p.clone()) {
            file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path.clone())
                .ok();
            if file.is_some() {
                file_path = Some(path);
                break;
            }
        }

        log::error!("{}", rust_i18n::t!("core_app.panic_backtrace_save"));

        // write str to stderr & file
        let mut write_err = |s: String| {
            let _ = stderr.write_all(s.as_bytes());
            if let Some(mut f) = file.as_ref() {
                let _ = f.write_all(s.as_bytes());
            }
        };

        let msg = formatdoc! {"
            panic occurred, if this is a bug, please report this issue on github (https://github.com/easytier/easytier/issues)
                easytier version: {version}
                os: {os}
                arch: {arch}
                panic is recorded in: {file}
                thread: {thread}
                time: {time}
                location: {location}
                panic info: {payload}
            ",
            version = crate::VERSION,
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            file = file_path
                .and_then(|p| p.to_str().map(|x| x.to_string()))
                .unwrap_or("<no file>".to_string()),
            thread = thread,
            time = chrono::Local::now(),
            location = location,
            payload = payload_str,
        };

        write_err(msg);
        write_err(sep);
        write_err(format!("{:#?}", backtrace::Backtrace::force_capture()));

        std::process::exit(1);
    }));
}
