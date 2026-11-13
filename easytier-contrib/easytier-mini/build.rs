use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    if !matches!(profile.as_str(), "release" | "mini")
        || !matches!(
            target.as_str(),
            "x86_64-unknown-linux-musl" | "mips-unknown-linux-musl" | "mipsel-unknown-linux-musl"
        )
    {
        return;
    }

    let script =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("easytier-mini-musl.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    // The release-derived mini profile already aborts panics. Keep the compact
    // binary's linker policy local so full EasyTier musl builds retain their
    // normal PIE/unwind settings.
    println!("cargo:rustc-link-arg-bin=easytier-mini=-Wl,--build-id=none");
    if target == "x86_64-unknown-linux-musl" {
        println!("cargo:rustc-link-arg-bin=easytier-mini=-Wl,--pack-dyn-relocs=relr");
        println!("cargo:rustc-link-arg-bin=easytier-mini=-Wl,--icf=all");
    }
    println!("cargo:rustc-link-arg-bin=easytier-mini=-Wl,--no-eh-frame-hdr");
    println!(
        "cargo:rustc-link-arg-bin=easytier-mini=-Wl,-T,{}",
        script.display()
    );
}
