use prost_reflect::{Cardinality, DescriptorPool, FieldDescriptor, Kind, MessageDescriptor};
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

const NETWORK_CONFIG_MESSAGE_NAME: &str = "api.manage.NetworkConfig";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldOption {
    label: String,
    value: String,
    numeric_value: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationRule {
    rule_type: String,
    arg: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkConfigSchema {
    node_kind: String,
    name: String,
    field_number: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_type: Option<String>,
    value_kind: String,
    is_list: bool,
    required: bool,
    deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_value_text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    enum_options: Vec<FieldOption>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    validations: Vec<ValidationRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<NetworkConfigSchema>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    definitions: Vec<NetworkConfigSchema>,
}

fn field_default_value_text(field: &FieldDescriptor) -> Option<String> {
    if field.is_list() || field.is_map() {
        return Some("[]".to_string());
    }
    match field.kind() {
        Kind::Bool => Some("false".to_string()),
        Kind::String | Kind::Bytes => Some("\"\"".to_string()),
        Kind::Int32
        | Kind::Sint32
        | Kind::Sfixed32
        | Kind::Int64
        | Kind::Sint64
        | Kind::Sfixed64
        | Kind::Uint32
        | Kind::Fixed32
        | Kind::Uint64
        | Kind::Fixed64
        | Kind::Float
        | Kind::Double => Some("0".to_string()),
        Kind::Enum(enum_desc) => enum_desc.get_value(0).map(|value| value.name().to_string()),
        Kind::Message(_) => None,
    }
}

fn field_type_name(field: &FieldDescriptor) -> Option<String> {
    match field.kind() {
        Kind::Enum(enum_desc) => Some(enum_desc.full_name().to_string()),
        Kind::Message(message_desc) => Some(message_desc.full_name().to_string()),
        _ => None,
    }
}

fn field_semantic_type(field: &FieldDescriptor) -> Option<String> {
    let semantic = match field.name() {
        "virtual_ipv4" | "vpn_portal_client_network_addr" => "cidr_ip",
        "network_length" | "vpn_portal_client_network_len" => "cidr_mask",
        "socks5_port"
        | "vpn_portal_listen_port"
        | "bind_port"
        | "dst_port"
        | "quic_listen_port" => "port",
        "network_secret" | "wireguard_private_key" | "local_private_key" | "credential_secret" => {
            "secret"
        }
        "peer_urls" => "peer[]",
        "proxy_cidrs" | "allowed_proxy_cidrs" => "cidr[]",
        "listener_urls" => "listener[]",
        "routes" => "route[]",
        "exit_nodes" => "ip[]",
        "relay_network_whitelist" => "network_name[]",
        "mapped_listeners" => "mapped_listener[]",
        "port_forwards" => "port_forward[]",
        "managed_credentials" => "managed_credential[]",
        _ => return None,
    };
    Some(semantic.to_string())
}

fn enum_options(kind: Kind) -> Vec<FieldOption> {
    match kind {
        Kind::Enum(enum_desc) => enum_desc
            .values()
            .map(|value| FieldOption {
                label: value.name().to_string(),
                value: value.name().to_string(),
                numeric_value: value.number(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn should_expose_field(field: &FieldDescriptor) -> bool {
    match field.containing_oneof() {
        Some(_) => field
            .field_descriptor_proto()
            .proto3_optional
            .unwrap_or(false),
        None => true,
    }
}

fn is_field_deprecated(field: &FieldDescriptor) -> bool {
    field
        .field_descriptor_proto()
        .options
        .as_ref()
        .and_then(|opts| opts.deprecated)
        .unwrap_or(false)
}

fn build_validations(field: &FieldDescriptor) -> Vec<ValidationRule> {
    if field.cardinality() == Cardinality::Required {
        return vec![ValidationRule {
            rule_type: "required".to_string(),
            arg: String::new(),
            message: format!("{} is required", field.name()),
        }];
    }
    Vec::new()
}

fn kind_to_value_kind(field: &FieldDescriptor) -> String {
    if field.is_map() {
        return "object".to_string();
    }
    match field.kind() {
        Kind::Bool => "boolean".to_string(),
        Kind::String | Kind::Bytes => "string".to_string(),
        Kind::Int32
        | Kind::Sint32
        | Kind::Sfixed32
        | Kind::Int64
        | Kind::Sint64
        | Kind::Sfixed64
        | Kind::Uint32
        | Kind::Fixed32
        | Kind::Uint64
        | Kind::Fixed64
        | Kind::Float
        | Kind::Double => "number".to_string(),
        Kind::Enum(_) => "enum".to_string(),
        Kind::Message(_) => "object".to_string(),
    }
}

fn build_map_entry_node(
    message_desc: &MessageDescriptor,
    path: &mut Vec<String>,
    reachable: &mut BTreeMap<String, NetworkConfigSchema>,
) -> NetworkConfigSchema {
    let key_field = message_desc.map_entry_key_field();
    let value_field = message_desc.map_entry_value_field();
    NetworkConfigSchema {
        node_kind: "object".to_string(),
        name: message_desc.name().to_string(),
        field_number: 0,
        type_name: Some(message_desc.full_name().to_string()),
        semantic_type: None,
        value_kind: "object".to_string(),
        is_list: false,
        required: true,
        deprecated: false,
        default_value_text: None,
        enum_options: Vec::new(),
        validations: Vec::new(),
        children: vec![
            build_schema_field_node(&key_field, path, reachable),
            build_schema_field_node(&value_field, path, reachable),
        ],
        definitions: Vec::new(),
    }
}

fn field_children(
    field: &FieldDescriptor,
    path: &mut Vec<String>,
    reachable: &mut BTreeMap<String, NetworkConfigSchema>,
) -> Vec<NetworkConfigSchema> {
    if field.is_map()
        && let Kind::Message(message_desc) = field.kind()
    {
        return vec![build_map_entry_node(&message_desc, path, reachable)];
    }
    match field.kind() {
        Kind::Message(message_desc) => {
            let children = build_message_children(&message_desc, path, reachable);
            let full_name = message_desc.full_name().to_string();
            if full_name != NETWORK_CONFIG_MESSAGE_NAME
                && !message_desc.is_map_entry()
                && !reachable.contains_key(&full_name)
            {
                reachable.insert(
                    full_name.clone(),
                    NetworkConfigSchema {
                        node_kind: "object".to_string(),
                        name: full_name.clone(),
                        field_number: 0,
                        type_name: Some(full_name),
                        semantic_type: None,
                        value_kind: "object".to_string(),
                        is_list: false,
                        required: true,
                        deprecated: false,
                        default_value_text: None,
                        enum_options: Vec::new(),
                        validations: Vec::new(),
                        children: children.clone(),
                        definitions: Vec::new(),
                    },
                );
            }
            children
        }
        Kind::Enum(enum_desc) => {
            let full_name = enum_desc.full_name().to_string();
            if !reachable.contains_key(&full_name) {
                reachable.insert(
                    full_name.clone(),
                    NetworkConfigSchema {
                        node_kind: "enum".to_string(),
                        name: full_name.clone(),
                        field_number: 0,
                        type_name: Some(full_name),
                        semantic_type: None,
                        value_kind: "enum".to_string(),
                        is_list: false,
                        required: false,
                        deprecated: false,
                        default_value_text: None,
                        enum_options: enum_options(Kind::Enum(enum_desc)),
                        validations: Vec::new(),
                        children: Vec::new(),
                        definitions: Vec::new(),
                    },
                );
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn build_message_children(
    message_desc: &MessageDescriptor,
    path: &mut Vec<String>,
    reachable: &mut BTreeMap<String, NetworkConfigSchema>,
) -> Vec<NetworkConfigSchema> {
    let full_name = message_desc.full_name().to_string();
    if path.contains(&full_name) {
        return Vec::new();
    }
    path.push(full_name);
    let mut children = Vec::new();
    for field in message_desc.fields().filter(should_expose_field) {
        children.push(build_schema_field_node(&field, path, reachable));
    }
    path.pop();
    children
}

fn build_schema_field_node(
    field: &FieldDescriptor,
    path: &mut Vec<String>,
    reachable: &mut BTreeMap<String, NetworkConfigSchema>,
) -> NetworkConfigSchema {
    NetworkConfigSchema {
        node_kind: "field".to_string(),
        name: field.name().to_string(),
        field_number: field.number() as i32,
        type_name: field_type_name(field),
        semantic_type: field_semantic_type(field),
        value_kind: kind_to_value_kind(field),
        is_list: field.is_list() || field.is_map(),
        required: field.cardinality() == Cardinality::Required,
        deprecated: is_field_deprecated(field),
        default_value_text: field_default_value_text(field),
        enum_options: enum_options(field.kind()),
        validations: build_validations(field),
        children: field_children(field, path, reachable),
        definitions: Vec::new(),
    }
}

fn generate_network_config_schema() {
    println!("cargo:rerun-if-changed=build.rs");

    let pool = DescriptorPool::decode(easytier_proto::ALL_DESCRIPTOR_BYTES)
        .expect("easytier-proto ALL_DESCRIPTOR_BYTES should decode");
    let network_config = pool
        .get_message_by_name(NETWORK_CONFIG_MESSAGE_NAME)
        .expect("api.manage.NetworkConfig descriptor should exist");

    let mut reachable = BTreeMap::new();
    let children = build_message_children(&network_config, &mut Vec::new(), &mut reachable);
    let schema = NetworkConfigSchema {
        node_kind: "schema".to_string(),
        name: network_config.name().to_string(),
        field_number: 0,
        type_name: Some(network_config.full_name().to_string()),
        semantic_type: None,
        value_kind: "object".to_string(),
        is_list: false,
        required: true,
        deprecated: false,
        default_value_text: None,
        enum_options: Vec::new(),
        validations: Vec::new(),
        children,
        definitions: reachable.into_values().collect(),
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let schema_json = serde_json::to_string(&schema).expect("serialize NetworkConfigSchema");
    fs::write(out_dir.join("network_config_schema.json"), schema_json)
        .expect("write network_config_schema.json");

    let mut mappings_code =
        String::from("pub const NETWORK_CONFIG_FIELD_MAPPINGS: &[(&str, i32)] = &[\n");
    for field in network_config.fields().filter(should_expose_field) {
        mappings_code.push_str(&format!("    ({:?}, {}),\n", field.name(), field.number()));
    }
    mappings_code.push_str("];\n");
    fs::write(
        out_dir.join("network_config_field_mappings.rs"),
        mappings_code,
    )
    .expect("write network_config_field_mappings.rs");
}

fn main() {
    napi_build_ohos::setup();
    generate_network_config_schema();
}
