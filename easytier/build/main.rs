use cfg_aliases::cfg_aliases;
use std::env;

#[cfg(target_os = "windows")]
struct WindowsBuild {}

#[cfg(target_os = "windows")]
impl WindowsBuild {
    pub fn check_for_win() {
        // add third_party dir to link search path
        let target = std::env::var("TARGET").unwrap_or_default();

        if target.contains("x86_64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/x86_64/");
        } else if target.contains("i686") {
            println!("cargo:rustc-link-search=native=easytier/third_party/i686/");
        } else if target.contains("aarch64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/arm64/");
        }
    }
}

fn workdir() -> Option<String> {
    if let Ok(cargo_manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        return Some(cargo_manifest_dir);
    }

    let dest = std::env::var("OUT_DIR");
    if dest.is_err() {
        return None;
    }
    let dest = dest.unwrap();

    let seperator = regex::Regex::new(r"(/target/(.+?)/build/)|(\\target\\(.+?)\\build\\)")
        .expect("Invalid regex");
    let parts = seperator.split(dest.as_str()).collect::<Vec<_>>();

    if parts.len() >= 2 {
        return Some(parts[0].to_string());
    }

    None
}

fn check_locale() {
    let workdir = workdir().unwrap_or("./".to_string());

    let locale_path = format!("{workdir}/**/locales/**/*");
    if let Ok(globs) = globwalk::glob(locale_path) {
        for entry in globs {
            if let Err(e) = entry {
                println!("cargo:i18n-error={e}");
                continue;
            }

            let entry = entry.unwrap().into_path();
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cfg_aliases! {
        mobile: {
            any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            )
        }
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    // enable thunk-rs when target os is windows and arch is x86_64 or i686
    if target_os == "windows" && (target_arch == "x86" || target_arch == "x86_64") {
        thunk::thunk();
    }

    #[cfg(target_os = "windows")]
    WindowsBuild::check_for_win();

    check_locale();
    Ok(())
}
