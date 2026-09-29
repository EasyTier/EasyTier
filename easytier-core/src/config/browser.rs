use wasm_bindgen::prelude::*;

use super::{
    api_input::{NetworkConfig, NetworkConfigExt, merge_network_config_toml, network_config_from_raw},
    parse_instance_config, serialize_raw_to_toml,
};

fn js_error(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{error:?}"))
}

#[wasm_bindgen]
pub fn generate_config(config_json: &str) -> Result<String, JsValue> {
    let config: NetworkConfig = serde_json::from_str(config_json).map_err(js_error)?;
    let instance_config = config.gen_config().map_err(js_error)?;
    serialize_raw_to_toml(instance_config.raw()).map_err(js_error)
}

#[wasm_bindgen]
pub fn merge_config(original_toml: &str, config_json: &str) -> Result<String, JsValue> {
    let config: NetworkConfig = serde_json::from_str(config_json).map_err(js_error)?;
    merge_network_config_toml(original_toml, &config).map_err(js_error)
}

#[wasm_bindgen]
pub fn parse_config(toml_config: &str) -> Result<String, JsValue> {
    let config = parse_instance_config("browser", toml_config)
        .map(|config| network_config_from_raw(config.raw()))
        .map_err(js_error)?;
    serde_json::to_string(&config).map_err(js_error)
}
