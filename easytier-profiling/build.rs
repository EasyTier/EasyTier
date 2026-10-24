fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(all(feature = "lttng", target_os = "linux"))]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        generate();
    }
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
fn generate() {
    use lttng_ust_generate::{CIntegerType, CTFType, Generator, Provider};
    let mut provider = Provider::new("easytier");
    provider
        .create_class("span_metadata")
        .add_field("id", CTFType::Integer(CIntegerType::U64))
        .add_field("parent", CTFType::Integer(CIntegerType::U64))
        .add_field("name", CTFType::SequenceText)
        .add_field("target", CTFType::SequenceText)
        .add_field("fields", CTFType::SequenceText)
        .instantiate("span_new");
    provider
        .create_class("span_lifecycle")
        .add_field("id", CTFType::Integer(CIntegerType::U64))
        .instantiate("span_enter")
        .instantiate("span_exit")
        .instantiate("span_close");
    provider
        .create_class("span_record")
        .add_field("id", CTFType::Integer(CIntegerType::U64))
        .add_field("fields", CTFType::SequenceText)
        .instantiate("span_record");
    provider
        .create_class("span_link")
        .add_field("id", CTFType::Integer(CIntegerType::U64))
        .add_field("follows", CTFType::Integer(CIntegerType::U64))
        .instantiate("span_follows_from");
    provider
        .create_class("event")
        .add_field("parent", CTFType::Integer(CIntegerType::U64))
        .add_field("name", CTFType::SequenceText)
        .add_field("target", CTFType::SequenceText)
        .add_field("level", CTFType::SequenceText)
        .add_field("fields", CTFType::SequenceText)
        .instantiate("event");
    Generator::default()
        .generated_lib_name("easytier_profiling_tracepoints")
        .register_provider(provider)
        .output_file_name(
            std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("tracepoints.rs"),
        )
        .generate()
        .expect("generate EasyTier LTTng tracepoints");
}
