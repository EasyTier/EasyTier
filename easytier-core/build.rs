#[cfg(target_os = "windows")]
use std::{
    env,
    fs::File,
    io::{copy, Cursor},
    path::PathBuf,
};

#[cfg(target_os = "windows")]
struct WindowsBuild {}

#[cfg(target_os = "windows")]
impl WindowsBuild {
    fn check_protoc_exist() -> Option<PathBuf> {
        let path = env::var_os("PROTOC").map(PathBuf::from);
        if path.is_some() && path.as_ref().unwrap().exists() {
            return path;
        }

        let path = env::var_os("PATH").unwrap_or_default();
        for p in env::split_paths(&path) {
            let p = p.join("protoc");
            if p.exists() {
                return Some(p);
            }
        }

        None
    }

    fn get_cargo_target_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        let profile = std::env::var("PROFILE")?;
        let mut target_dir = None;
        let mut sub_path = out_dir.as_path();
        while let Some(parent) = sub_path.parent() {
            if parent.ends_with(&profile) {
                target_dir = Some(parent);
                break;
            }
            sub_path = parent;
        }
        let target_dir = target_dir.ok_or("not found")?;
        Ok(target_dir.to_path_buf())
    }

    fn download_protoc() -> PathBuf {
        println!("cargo:info=use exist protoc: {:?}", "k");
        let out_dir = Self::get_cargo_target_dir().unwrap();
        let fname = out_dir.join("protoc");
        if fname.exists() {
            println!("cargo:info=use exist protoc: {:?}", fname);
            return fname;
        }

        println!("cargo:info=need download protoc, please wait...");

        let url = "https://github.com/protocolbuffers/protobuf/releases/download/v26.0-rc1/protoc-26.0-rc-1-win64.zip";
        let response = reqwest::blocking::get(url).unwrap();
        println!("{:?}", response);
        let mut content = response
            .bytes()
            .map(|v| v.to_vec())
            .map(Cursor::new)
            .map(zip::ZipArchive::new)
            .unwrap()
            .unwrap();
        let protoc_zipped_file = content.by_name("bin/protoc.exe").unwrap();
        let mut content = protoc_zipped_file;

        copy(&mut content, &mut File::create(&fname).unwrap()).unwrap();

        fname
    }

    pub fn check_for_win() {
        // add third_party dir to link search path
        println!("cargo:rustc-link-search=native=third_party/");
        let protoc_path = if let Some(o) = Self::check_protoc_exist() {
            println!("cargo:info=use os exist protoc: {:?}", o);
            o
        } else {
            Self::download_protoc()
        };
        std::env::set_var("PROTOC", protoc_path);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    WindowsBuild::check_for_win();

    tonic_build::compile_protos("proto/cli.proto")?;
    Ok(())
}
