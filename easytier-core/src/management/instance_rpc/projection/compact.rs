use crate::instance::{CoreInstance, CoreInstanceHost};

pub(in crate::management::instance_rpc) fn format_last_update(
    last_update: &easytier_proto::common::RuntimeTimestamp,
) -> anyhow::Result<String> {
    let last_update = last_update.normalized();
    let date_time = chrono::DateTime::from_timestamp(last_update.seconds, last_update.nanos as u32)
        .ok_or_else(|| anyhow::anyhow!("invalid protobuf timestamp"))?;
    Ok(format!("\"{date_time:?}\""))
}

pub(in crate::management::instance_rpc) fn node_config<H>(
    _instance: &CoreInstance<H>,
) -> anyhow::Result<String>
where
    H: CoreInstanceHost,
{
    Ok(String::new())
}
