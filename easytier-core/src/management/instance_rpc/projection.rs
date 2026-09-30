use crate::instance::{CoreInstance, CoreInstanceHost};

#[cfg(not(feature = "management"))]
pub(super) fn format_last_update(
    last_update: &easytier_proto::common::RuntimeTimestamp,
) -> anyhow::Result<String> {
    let last_update = last_update.normalized();
    let date_time = chrono::DateTime::from_timestamp(last_update.seconds, last_update.nanos as u32)
        .ok_or_else(|| anyhow::anyhow!("invalid protobuf timestamp"))?;
    Ok(format!("\"{date_time:?}\""))
}

#[cfg(feature = "management")]
pub(super) fn format_last_update(
    last_update: &easytier_proto::common::RuntimeTimestamp,
) -> anyhow::Result<String> {
    serde_json::to_string(last_update).map_err(anyhow::Error::from)
}

#[cfg(not(feature = "management"))]
pub(super) fn node_config<H>(_instance: &CoreInstance<H>) -> anyhow::Result<String>
where
    H: CoreInstanceHost,
{
    Ok(String::new())
}

#[cfg(feature = "management")]
pub(super) fn node_config<H>(instance: &CoreInstance<H>) -> anyhow::Result<String>
where
    H: CoreInstanceHost,
{
    let snapshot = instance.config_store().snapshot();
    crate::config::serialize_raw_to_toml(snapshot.raw()).map_err(|e| anyhow::anyhow!(e))
}
