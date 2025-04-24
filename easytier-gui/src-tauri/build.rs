fn main() {
	// enable thunk-rs when target os is windows and arch is i686
	#[cfg(target_os = "windows")]
    if !std::env::var("TARGET").unwrap_or_default().contains("aarch64"){
        thunk::thunk();
    }

    tauri_build::build();
}
