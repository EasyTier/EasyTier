use crate::config::schema::get_network_config_field_mappings;
use crate::napi_types::SharedConfigLinkPayload;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use easytier::proto::api::manage::NetworkConfig;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use gethostname::gethostname;
use std::collections::HashMap;
use std::io::{Read, Write};
use url::Url;
use uuid::Uuid;

const SHARE_LINK_HOST: &str = "easytier.cn";
const SHARE_LINK_PATH: &str = "/comp_cfg";

fn field_name_to_id_map() -> HashMap<String, String> {
    get_network_config_field_mappings()
        .into_iter()
        .map(|mapping| (mapping.field_name, mapping.field_number.to_string()))
        .collect()
}

fn field_id_to_name_map() -> HashMap<String, String> {
    get_network_config_field_mappings()
        .into_iter()
        .map(|mapping| (mapping.field_number.to_string(), mapping.field_name))
        .collect()
}

fn prune_empty(value: &serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Array(values) if values.is_empty() => None,
        _ => Some(value.clone()),
    }
}

fn map_config_json(config: &NetworkConfig) -> Result<String, String> {
    let field_name_to_id = field_name_to_id_map();
    let raw = serde_json::to_value(config).map_err(|err| err.to_string())?;
    let mut mapped = serde_json::Map::new();

    for (key, value) in raw.as_object().cloned().unwrap_or_default() {
        let Some(value) = prune_empty(&value) else {
            continue;
        };
        let mapped_key = field_name_to_id.get(&key).cloned().unwrap_or(key);
        mapped.insert(mapped_key, value);
    }

    serde_json::to_string(&mapped).map_err(|err| err.to_string())
}

fn unmap_config_json(raw: &str) -> Result<NetworkConfig, String> {
    let field_id_to_name = field_id_to_name_map();
    let value = serde_json::from_str::<serde_json::Value>(raw).map_err(|err| err.to_string())?;
    let mut mapped = serde_json::Map::new();
    for (key, value) in value.as_object().cloned().unwrap_or_default() {
        let field_name = field_id_to_name.get(&key).cloned().unwrap_or(key);
        mapped.insert(field_name, value);
    }
    serde_json::from_value(serde_json::Value::Object(mapped)).map_err(|err| err.to_string())
}

fn compress_to_base64url(raw: &str) -> Result<String, String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(raw.as_bytes())
        .map_err(|err| err.to_string())?;
    let compressed = encoder.finish().map_err(|err| err.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(compressed))
}

fn decompress_from_base64url(raw: &str) -> Result<String, String> {
    let compressed = URL_SAFE_NO_PAD.decode(raw).map_err(|err| err.to_string())?;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .map_err(|err| err.to_string())?;
    Ok(out)
}

pub fn build_config_share_link_from_json(
    config_json: &str,
    display_name: Option<String>,
    only_start: bool,
) -> Option<String> {
    let config = serde_json::from_str::<NetworkConfig>(config_json).ok()?;
    let mapped_json = map_config_json(&config).ok()?;
    let compressed = compress_to_base64url(&mapped_json).ok()?;
    let final_name = display_name.filter(|name| !name.is_empty());

    let mut url = Url::parse(&format!("https://{SHARE_LINK_HOST}{SHARE_LINK_PATH}")).ok()?;
    url.query_pairs_mut().append_pair("cfg", &compressed);
    if let Some(name) = final_name {
        url.query_pairs_mut().append_pair("name", &name);
    }
    if only_start {
        url.query_pairs_mut().append_pair("only_start", "true");
    }
    Some(url.to_string())
}

pub fn parse_config_share_link(share_link: &str) -> Option<SharedConfigLinkPayload> {
    let url = Url::parse(share_link).ok()?;
    if url.host_str()? != SHARE_LINK_HOST || url.path() != SHARE_LINK_PATH {
        return None;
    }

    let cfg = url
        .query_pairs()
        .find(|(key, _)| key == "cfg")?
        .1
        .to_string();
    let mapped_json = decompress_from_base64url(&cfg).ok()?;
    let mut config = unmap_config_json(&mapped_json).ok()?;
    config.instance_id = Some(Uuid::new_v4().to_string());
    let hostname = gethostname().to_string_lossy().to_string();
    if !hostname.is_empty() {
        config.hostname = Some(hostname);
    }

    let config_json = serde_json::to_string(&config).ok()?;
    let display_name = url
        .query_pairs()
        .find(|(key, _)| key == "name")
        .map(|(_, value)| value.to_string())
        .filter(|name| !name.is_empty());
    let only_start = url
        .query_pairs()
        .find(|(key, _)| key == "only_start")
        .map(|(_, value)| value == "true")
        .unwrap_or(false);

    Some(SharedConfigLinkPayload {
        config_json,
        display_name,
        only_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repository::get_default_config_json;

    #[test]
    fn share_link_roundtrip_works_statelessly() {
        let mut raw = serde_json::from_str::<NetworkConfig>(
            &get_default_config_json().expect("default config"),
        )
        .expect("parse default");
        const CONFIG_ID: &str = "00000000-0000-0000-0000-000000000003";
        raw.instance_id = Some(CONFIG_ID.to_string());
        raw.network_name = Some("demo-net".to_string());
        let json = serde_json::to_string(&raw).expect("serialize");

        let link = build_config_share_link_from_json(&json, Some("share-demo".to_string()), true)
            .expect("share link");
        let payload = parse_config_share_link(&link).expect("parse link");
        let config =
            serde_json::from_str::<NetworkConfig>(&payload.config_json).expect("config json");

        assert!(payload.only_start);
        assert_eq!(payload.display_name.as_deref(), Some("share-demo"));
        assert_eq!(config.network_name.as_deref(), Some("demo-net"));
        assert_ne!(config.instance_id.as_deref(), Some(CONFIG_ID));
    }
}
