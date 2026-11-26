use crate::napi_types::ConfigFieldMapping;

include!(concat!(
    env!("OUT_DIR"),
    "/network_config_field_mappings.rs"
));

/// Compact camelCase JSON schema for `api.manage.NetworkConfig` generated at
/// compile time directly from `easytier_proto::ALL_DESCRIPTOR_BYTES` in `build.rs`.
/// Zero runtime `prost-reflect` / `DescriptorPool` memory overhead.
pub const NETWORK_CONFIG_SCHEMA_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/network_config_schema.json"));

pub fn get_network_config_schema_json() -> &'static str {
    NETWORK_CONFIG_SCHEMA_JSON
}

pub fn get_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    NETWORK_CONFIG_FIELD_MAPPINGS
        .iter()
        .map(|(name, number)| ConfigFieldMapping {
            field_name: (*name).to_string(),
            field_number: *number,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_schema_contains_core_fields_and_enums() {
        let json = get_network_config_schema_json();
        let value: serde_json::Value =
            serde_json::from_str(json).expect("schema json should parse");
        assert_eq!(value["nodeKind"], "schema");
        assert_eq!(value["name"], "NetworkConfig");
        let children = value["children"].as_array().expect("schema children array");
        assert!(children.iter().any(|f| f["name"] == "network_name"));
        assert!(
            children
                .iter()
                .any(|f| f["name"] == "peer_urls" && f["semanticType"] == "peer[]")
        );
        let compress = children
            .iter()
            .find(|f| f["name"] == "data_compress_algo")
            .expect("data_compress_algo field");
        let options = compress["enumOptions"].as_array().expect("enumOptions");
        assert!(options.iter().any(|o| o["label"] == "None"));
        assert!(options.iter().any(|o| o["label"] == "Zstd"));
        assert!(
            children
                .iter()
                .any(|f| f["name"] == "port_forwards" && f["isList"] == true)
        );
        assert!(
            children
                .iter()
                .any(|f| f["name"] == "dns" && f["valueKind"] == "object")
        );
    }

    #[test]
    fn compile_time_field_mappings_cover_core_fields() {
        let mappings = get_network_config_field_mappings();
        assert!(
            mappings
                .iter()
                .any(|m| m.field_name == "network_name" && m.field_number == 6)
        );
        assert!(
            mappings
                .iter()
                .any(|m| m.field_name == "peer_urls" && m.field_number == 10)
        );
        assert!(
            mappings
                .iter()
                .any(|m| m.field_name == "enable_magic_dns" && m.field_number == 42)
        );
    }
}
