use wasm_bindgen::prelude::*;

use super::{
    api_input::{NetworkConfig, NetworkConfigExt},
    toml::{ConfigLoader, TomlConfig},
};

fn js_error(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{error:?}"))
}

#[wasm_bindgen]
pub fn generate_config(config_json: &str) -> Result<String, JsValue> {
    let config: NetworkConfig = serde_json::from_str(config_json).map_err(js_error)?;
    config
        .gen_config()
        .map(|config| config.dump())
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn parse_config(toml_config: &str) -> Result<String, JsValue> {
    let config = TomlConfig::new_from_str(toml_config)
        .and_then(|config| NetworkConfig::new_from_config(&config))
        .map_err(js_error)?;
    serde_json::to_string(&config).map_err(js_error)
}
