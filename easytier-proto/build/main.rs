mod rpc;

use crate::rpc::ServiceGenerator;
use std::{env, path::PathBuf};

#[cfg(target_os = "windows")]
use std::io::Cursor;

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn get_cargo_target_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let profile = env::var("PROFILE")?;
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

#[cfg(target_os = "windows")]
fn download_protoc() -> PathBuf {
    let out_dir = get_cargo_target_dir().unwrap().join("protobuf");
    let fname = out_dir.join("bin/protoc.exe");
    if fname.exists() {
        println!("cargo:info=use existing protoc: {:?}", fname);
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

#[cfg(target_os = "windows")]
fn ensure_protoc_for_windows() {
    let protoc_path = if let Some(path) = check_protoc_exist() {
        println!("cargo:info=use os existing protoc: {:?}", path);
        path
    } else {
        download_protoc()
    };

    unsafe {
        env::set_var("PROTOC", protoc_path);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    ensure_protoc_for_windows();

    let proto_files_reflect = ["proto/peer_rpc.proto", "proto/common.proto"];

    let proto_files = [
        "proto/core_peer.proto",
        "proto/core_config.proto",
        "proto/error.proto",
        "proto/tests.proto",
        "proto/api_instance.proto",
        "proto/api_logger.proto",
        "proto/api_config.proto",
        "proto/api_manage.proto",
        "proto/web.proto",
        "proto/magic_dns.proto",
        "proto/acl.proto",
    ];

    for proto_file in proto_files.iter().chain(proto_files_reflect.iter()) {
        println!("cargo:rerun-if-changed={proto_file}");
    }

    let out = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor = out.join("descriptors.bin");

    let mut config = prost_build::Config::new();
    if env::var_os("CARGO_FEATURE_JSON_RPC").is_some() {
        config
            .extern_path(".google.protobuf.Any", "::prost_wkt_types::Any")
            .extern_path(".google.protobuf.Timestamp", "::prost_wkt_types::Timestamp")
            .extern_path(".google.protobuf.Value", "::prost_wkt_types::Value");
    } else {
        config
            .extern_path(".google.protobuf.Any", "::prost_types::Any")
            .extern_path(".google.protobuf.Timestamp", "::prost_types::Timestamp")
            .extern_path(".google.protobuf.Value", "::prost_types::Value");
    }
    config
        .file_descriptor_set_path(&descriptor)
        .service_generator(Box::new(ServiceGenerator::default()))
        .btree_map(["."])
        .skip_debug([".common.Ipv4Addr", ".common.Ipv6Addr", ".common.UUID"]);

    config.compile_protos(&proto_files, &["proto/"])?;

    config.file_descriptor_set_path(out.join("file_descriptor_set.bin"));
    config.compile_protos(&proto_files_reflect, &["proto/"])?;

    let descriptor = std::fs::read(descriptor)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor)?
        .preserve_proto_field_names()
        .btree_map(["."])
        .build(&["."])?;

    Ok(())
}
