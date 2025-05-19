#[cfg(target_os = "windows")]
use std::{env, io::Cursor, path::PathBuf};

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
            let p = p.join("protoc.exe");
            if p.exists() && p.is_file() {
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
        let out_dir = Self::get_cargo_target_dir().unwrap().join("protobuf");
        let fname = out_dir.join("bin/protoc.exe");
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
        content.extract(out_dir).unwrap();

        fname
    }

    pub fn check_for_win() {
        // add third_party dir to link search path
        let target = std::env::var("TARGET").unwrap_or_default();

        if target.contains("x86_64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/");
        } else if target.contains("i686") {
            println!("cargo:rustc-link-search=native=easytier/third_party/i686/");
        } else if target.contains("aarch64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/arm64/");
        }

        let protoc_path = if let Some(o) = Self::check_protoc_exist() {
            println!("cargo:info=use os exist protoc: {:?}", o);
            o
        } else {
            Self::download_protoc()
        };
        std::env::set_var("PROTOC", protoc_path);
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
                println!("cargo:i18n-error={}", e);
                continue;
            }

            let entry = entry.unwrap().into_path();
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // enable thunk-rs when target os is windows and arch is x86_64 or i686
    #[cfg(target_os = "windows")]
    if !std::env::var("TARGET")
        .unwrap_or_default()
        .contains("aarch64")
    {
        thunk::thunk();
    }

    #[cfg(target_os = "windows")]
    WindowsBuild::check_for_win();

    let proto_files_reflect = ["src/proto/peer_rpc.proto", "src/proto/common.proto"];

    let proto_files = [
        "src/proto/error.proto",
        "src/proto/tests.proto",
        "src/proto/cli.proto",
        "src/proto/web.proto",
        "src/proto/magic_dns.proto",
    ];

    for proto_file in proto_files.iter().chain(proto_files_reflect.iter()) {
        println!("cargo:rerun-if-changed={}", proto_file);
    }

    let mut config = prost_build::Config::new();
    config
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(".common", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".error", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".cli", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".web", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(
            "peer_rpc.GetIpListResponse",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute("peer_rpc.DirectConnectedPeerInfo", "#[derive(Hash)]")
        .type_attribute("peer_rpc.PeerInfoForGlobalMap", "#[derive(Hash)]")
        .type_attribute("peer_rpc.ForeignNetworkRouteInfoKey", "#[derive(Hash, Eq)]")
        .type_attribute("common.RpcDescriptor", "#[derive(Hash, Eq)]")
        .field_attribute(".web.NetworkConfig", "#[serde(default)]")
        .service_generator(Box::new(rpc_build::ServiceGenerator::new()))
        .btree_map(["."]);

    config.compile_protos(&proto_files, &["src/proto/"])?;

    prost_reflect_build::Builder::new()
        .file_descriptor_set_bytes("crate::proto::DESCRIPTOR_POOL_BYTES")
        .compile_protos_with_config(config, &proto_files_reflect, &["src/proto/"])?;

    check_locale();
    Ok(())
}
