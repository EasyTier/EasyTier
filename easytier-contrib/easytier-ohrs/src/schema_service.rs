use easytier::proto::ALL_DESCRIPTOR_BYTES;
use napi_derive_ohos::napi;
use once_cell::sync::Lazy;
use prost_reflect::{Cardinality, DescriptorPool, FieldDescriptor, Kind, MessageDescriptor};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct FieldOption {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct ValidationRule {
    pub rule_type: String,
    pub arg: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct NetworkConfigSchema {
    pub node_kind: String,
    pub name: String,
    pub field_number: i32,
    pub type_name: Option<String>,
    pub semantic_type: Option<String>,
    pub value_kind: String,
    pub is_list: bool,
    pub required: bool,
    pub default_value_text: Option<String>,
    pub enum_options: Vec<FieldOption>,
    pub validations: Vec<ValidationRule>,
    pub children: Vec<NetworkConfigSchema>,
    pub definitions: Vec<NetworkConfigSchema>,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct ConfigFieldMapping {
    pub field_name: String,
    pub field_number: i32,
}

static DESCRIPTOR_POOL: Lazy<DescriptorPool> = Lazy::new(|| {
    DescriptorPool::decode(ALL_DESCRIPTOR_BYTES)
        .expect("easytier descriptor pool should decode from embedded protobuf descriptors")
});

const NETWORK_CONFIG_MESSAGE_NAME: &str = "api.manage.NetworkConfig";

fn descriptor_pool() -> &'static DescriptorPool {
    &DESCRIPTOR_POOL
}

fn network_config_descriptor() -> MessageDescriptor {
    descriptor_pool()
        .get_message_by_name(NETWORK_CONFIG_MESSAGE_NAME)
        .expect("api.manage.NetworkConfig descriptor should exist")
}

fn field_default_value_text(field: &FieldDescriptor) -> Option<String> {
    if field.is_list() || field.is_map() {
        return Some("[]".to_string());
    }

    match field.kind() {
        Kind::Bool => Some("false".to_string()),
        Kind::String => Some("\"\"".to_string()),
        Kind::Bytes => Some("\"\"".to_string()),
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
        Kind::Enum(enum_desc) => enum_desc.get_value(0).map(|value| value.number().to_string()),
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
    match field.name() {
        "virtual_ipv4" => Some("cidr_ip".to_string()),
        "network_length" => Some("cidr_mask".to_string()),
        "peer_urls" => Some("peer[]".to_string()),
        "proxy_cidrs" => Some("cidr[]".to_string()),
        "listener_urls" => Some("listener[]".to_string()),
        "routes" => Some("route[]".to_string()),
        "exit_nodes" => Some("ip[]".to_string()),
        "relay_network_whitelist" => Some("network_name[]".to_string()),
        "mapped_listeners" => Some("mapped_listener[]".to_string()),
        "port_forwards" => Some("port_forward[]".to_string()),
        _ => None,
    }
}

fn enum_options(kind: Kind) -> Vec<FieldOption> {
    match kind {
        Kind::Enum(enum_desc) => enum_desc
            .values()
            .map(|value| FieldOption {
                label: value.name().to_string(),
                value: value.number().to_string(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn should_expose_field(field: &FieldDescriptor) -> bool {
    match field.containing_oneof() {
        Some(_) => field.field_descriptor_proto().proto3_optional.unwrap_or(false),
        None => true,
    }
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

fn build_node(
    node_kind: &str,
    name: String,
    field_number: i32,
    type_name: Option<String>,
    semantic_type: Option<String>,
    value_kind: String,
    is_list: bool,
    required: bool,
    default_value_text: Option<String>,
    enum_options: Vec<FieldOption>,
    validations: Vec<ValidationRule>,
    children: Vec<NetworkConfigSchema>,
    definitions: Vec<NetworkConfigSchema>,
) -> NetworkConfigSchema {
    NetworkConfigSchema {
        node_kind: node_kind.to_string(),
        name,
        field_number,
        type_name,
        semantic_type,
        value_kind,
        is_list,
        required,
        default_value_text,
        enum_options,
        validations,
        children,
        definitions,
    }
}

fn build_map_entry_node(message_desc: &MessageDescriptor) -> NetworkConfigSchema {
    let key_field = message_desc.map_entry_key_field();
    let value_field = message_desc.map_entry_value_field();

    build_node(
        "object",
        message_desc.name().to_string(),
        0,
        Some(message_desc.full_name().to_string()),
        None,
        "object".to_string(),
        false,
        true,
        None,
        Vec::new(),
        Vec::new(),
        vec![build_schema_field_node(&key_field), build_schema_field_node(&value_field)],
        Vec::new(),
    )
}

fn field_children(field: &FieldDescriptor) -> Vec<NetworkConfigSchema> {
    if field.is_map() {
        if let Kind::Message(message_desc) = field.kind() {
            return vec![build_map_entry_node(&message_desc)];
        }
    }

    match field.kind() {
        Kind::Message(message_desc) => build_message_children(&message_desc),
        _ => Vec::new(),
    }
}

fn build_message_children(message_desc: &MessageDescriptor) -> Vec<NetworkConfigSchema> {
    message_desc
        .fields()
        .filter(should_expose_field)
        .map(|field| build_schema_field_node(&field))
        .collect()
}

fn build_schema_field_node(field: &FieldDescriptor) -> NetworkConfigSchema {
    build_node(
        "field",
        field.name().to_string(),
        field.number() as i32,
        field_type_name(field),
        field_semantic_type(field),
        kind_to_value_kind(field),
        field.is_list() || field.is_map(),
        field.cardinality() == Cardinality::Required,
        field_default_value_text(field),
        enum_options(field.kind()),
        build_validations(field),
        field_children(field),
        Vec::new(),
    )
}

fn collect_definitions() -> Vec<NetworkConfigSchema> {
    let mut definitions = Vec::new();

    for message_desc in descriptor_pool().all_messages() {
        let full_name = message_desc.full_name();
        if full_name == NETWORK_CONFIG_MESSAGE_NAME || message_desc.is_map_entry() {
            continue;
        }

        definitions.push(build_node(
            "object",
            full_name.to_string(),
            0,
            Some(full_name.to_string()),
            None,
            "object".to_string(),
            false,
            true,
            None,
            Vec::new(),
            Vec::new(),
            build_message_children(&message_desc),
            Vec::new(),
        ));
    }

    for enum_desc in descriptor_pool().all_enums() {
        definitions.push(build_node(
            "enum",
            enum_desc.full_name().to_string(),
            0,
            Some(enum_desc.full_name().to_string()),
            None,
            "enum".to_string(),
            false,
            false,
            None,
            enum_options(Kind::Enum(enum_desc.clone())),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
    }

    definitions.sort_by(|a, b| a.name.cmp(&b.name));
    definitions
}

fn build_network_config_schema() -> NetworkConfigSchema {
    let network_config = network_config_descriptor();
    build_node(
        "schema",
        network_config.name().to_string(),
        0,
        Some(network_config.full_name().to_string()),
        None,
        "object".to_string(),
        false,
        true,
        None,
        Vec::new(),
        Vec::new(),
        build_message_children(&network_config),
        collect_definitions(),
    )
}

fn build_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    network_config_descriptor()
        .fields()
        .filter(should_expose_field)
        .map(|field| ConfigFieldMapping {
            field_name: field.name().to_string(),
            field_number: field.number() as i32,
        })
        .collect()
}

pub fn get_network_config_schema() -> NetworkConfigSchema {
    build_network_config_schema()
}

pub fn get_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    build_network_config_field_mappings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_exposed_as_single_tree_type() {
        let schema = get_network_config_schema();
        assert_eq!(schema.node_kind, "schema");
        assert_eq!(schema.name, "NetworkConfig");
        assert_eq!(schema.type_name.as_deref(), Some("api.manage.NetworkConfig"));

        let virtual_ipv4 = schema
            .children
            .iter()
            .find(|field| field.name == "virtual_ipv4")
            .expect("virtual_ipv4 field");
        assert_eq!(virtual_ipv4.semantic_type.as_deref(), Some("cidr_ip"));

        let secure_mode = schema
            .children
            .iter()
            .find(|field| field.name == "secure_mode")
            .expect("secure_mode field");
        assert!(secure_mode.children.iter().any(|field| field.name == "enabled"));

        let secure_mode_definition = schema
            .definitions
            .iter()
            .find(|definition| definition.name == "common.SecureModeConfig")
            .expect("secure mode definition");
        assert!(secure_mode_definition
            .children
            .iter()
            .any(|field| field.name == "local_private_key"));

        let networking_method_definition = schema
            .definitions
            .iter()
            .find(|definition| definition.name == "api.manage.NetworkingMethod")
            .expect("networking method enum definition");
        assert!(networking_method_definition
            .enum_options
            .iter()
            .any(|option| option.label == "PublicServer"));
    }
}
