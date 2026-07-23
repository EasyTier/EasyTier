use crate::{
    config::toml::ConfigLoader as _,
    instance::{CoreInstance, CoreInstanceHost},
};

pub(in crate::management::instance_rpc) fn format_last_update(
    last_update: &easytier_proto::common::RuntimeTimestamp,
) -> anyhow::Result<String> {
    serde_json::to_string(last_update).map_err(anyhow::Error::from)
}

pub(in crate::management::instance_rpc) fn node_config<H>(
    instance: &CoreInstance<H>,
) -> anyhow::Result<String>
where
    H: CoreInstanceHost,
{
    instance
        .toml_config()
        .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))
        .map(|config| config.dump())
}
