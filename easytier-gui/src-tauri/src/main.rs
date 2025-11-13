#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    if std::env::args().count() > 1 {
        app_lib::run_cli()
    } else {
        app_lib::run_gui()
    }
}
