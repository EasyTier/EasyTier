use std::{env, path::PathBuf};

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !matches!(target_os.as_str(), "android" | "linux") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let exports = manifest_dir.join("exports.map");
    println!("cargo:rerun-if-changed={}", exports.display());
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
        exports.display()
    );
    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-libs,ALL");
}
