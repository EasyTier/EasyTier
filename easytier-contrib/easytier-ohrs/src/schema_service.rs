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
pub struct SchemaFieldNode {
    pub field_name: String,
    pub field_number: i32,
    pub type_name: Option<String>,
    pub semantic_type: Option<String>,
    pub value_kind: String,
    pub is_list: bool,
    pub required: bool,
    pub default_value_text: Option<String>,
    pub enum_name: Option<String>,
    pub enum_options: Vec<FieldOption>,
    pub validations: Vec<ValidationRule>,
    pub children: Vec<SchemaFieldNode>,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct SchemaObjectDefinition {
    pub type_name: String,
    pub fields: Vec<SchemaFieldNode>,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct SchemaEnumDefinition {
    pub enum_name: String,
    pub options: Vec<FieldOption>,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct ConfigFieldMapping {
    pub field_name: String,
    pub field_number: i32,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct NetworkConfigSchema {
    pub schema_name: String,
    pub root: SchemaFieldNode,
    pub object_definitions: Vec<SchemaObjectDefinition>,
    pub enum_definitions: Vec<SchemaEnumDefinition>,
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

fn field_enum_name(field: &FieldDescriptor) -> Option<String> {
    match field.kind() {
        Kind::Enum(enum_desc) => Some(enum_desc.name().to_string()),
        _ => None,
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

fn field_enum_options(field: &FieldDescriptor) -> Vec<FieldOption> {
    match field.kind() {
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

fn field_children(field: &FieldDescriptor) -> Vec<SchemaFieldNode> {
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

fn build_map_entry_node(message_desc: &MessageDescriptor) -> SchemaFieldNode {
    let key_field = message_desc.map_entry_key_field();
    let value_field = message_desc.map_entry_value_field();

    SchemaFieldNode {
        field_name: message_desc.name().to_string(),
        field_number: 0,
        type_name: Some(message_desc.full_name().to_string()),
        semantic_type: None,
        value_kind: "object".to_string(),
        is_list: false,
        required: true,
        default_value_text: None,
        enum_name: None,
        enum_options: Vec::new(),
        validations: Vec::new(),
        children: vec![build_schema_field_node(&key_field), build_schema_field_node(&value_field)],
    }
}

fn should_expose_field(field: &FieldDescriptor) -> bool {
    match field.containing_oneof() {
        Some(_) => field.field_descriptor_proto().proto3_optional.unwrap_or(false),
        None => true,
    }
}

fn build_message_children(message_desc: &MessageDescriptor) -> Vec<SchemaFieldNode> {
    message_desc
        .fields()
        .filter(should_expose_field)
        .map(|field| build_schema_field_node(&field))
        .collect()
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

fn build_schema_field_node(field: &FieldDescriptor) -> SchemaFieldNode {
    SchemaFieldNode {
        field_name: field.name().to_string(),
        field_number: field.number() as i32,
        type_name: field_type_name(field),
        semantic_type: field_semantic_type(field),
        value_kind: kind_to_value_kind(field),
        is_list: field.is_list() || field.is_map(),
        required: field.cardinality() == Cardinality::Required,
        default_value_text: field_default_value_text(field),
        enum_name: field_enum_name(field),
        enum_options: field_enum_options(field),
        validations: build_validations(field),
        children: field_children(field),
    }
}

fn collect_object_definitions() -> Vec<SchemaObjectDefinition> {
    let mut definitions = Vec::new();
    for message_desc in descriptor_pool().all_messages() {
        let full_name = message_desc.full_name();
        if full_name == NETWORK_CONFIG_MESSAGE_NAME || message_desc.is_map_entry() {
            continue;
        }
        definitions.push(SchemaObjectDefinition {
            type_name: full_name.to_string(),
            fields: build_message_children(&message_desc),
        });
    }
    definitions.sort_by(|a, b| a.type_name.cmp(&b.type_name));
    definitions
}

fn collect_enum_definitions() -> Vec<SchemaEnumDefinition> {
    let mut definitions = Vec::new();
    for enum_desc in descriptor_pool().all_enums() {
        definitions.push(SchemaEnumDefinition {
            enum_name: enum_desc.full_name().to_string(),
            options: enum_desc
                .values()
                .map(|value| FieldOption {
                    label: value.name().to_string(),
                    value: value.number().to_string(),
                })
                .collect(),
        });
    }
    definitions.sort_by(|a, b| a.enum_name.cmp(&b.enum_name));
    definitions
}

fn build_network_config_schema() -> NetworkConfigSchema {
    let network_config = network_config_descriptor();
    NetworkConfigSchema {
        schema_name: network_config.name().to_string(),
        root: SchemaFieldNode {
            field_name: network_config.name().to_string(),
            field_number: 0,
            type_name: Some(network_config.full_name().to_string()),
            semantic_type: None,
            value_kind: "object".to_string(),
            is_list: false,
            required: true,
            default_value_text: None,
            enum_name: None,
            enum_options: Vec::new(),
            validations: Vec::new(),
            children: build_message_children(&network_config),
        },
        object_definitions: collect_object_definitions(),
        enum_definitions: collect_enum_definitions(),
    }
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
    fn nested_schema_object_contains_plain_field_tree() {
        let schema = get_network_config_schema();
        assert_eq!(schema.schema_name, "NetworkConfig");
        assert_eq!(schema.root.field_name, "NetworkConfig");
        assert_eq!(schema.root.type_name.as_deref(), Some("api.manage.NetworkConfig"));
        let virtual_ipv4 = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "virtual_ipv4")
            .expect("virtual_ipv4 field");
        assert_eq!(virtual_ipv4.semantic_type.as_deref(), Some("cidr_ip"));
        assert!(schema
            .root
            .children
            .iter()
            .any(|field| field.field_name == "instance_id"));
        assert!(schema
            .root
            .children
            .iter()
            .any(|field| field.field_name == "network_name"));
        assert!(schema
            .root
            .children
            .iter()
            .any(|field| field.field_name == "enable_vpn_portal"));
        let network_name = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "network_name")
            .expect("network_name field");
        assert!(network_name.field_number > 0);

        let secure_mode = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "secure_mode")
            .expect("secure_mode field");
        assert!(secure_mode
            .children
            .iter()
            .any(|field| field.field_name == "enabled"));
        assert_eq!(secure_mode.type_name.as_deref(), Some("common.SecureModeConfig"));

        let secure_mode_definition = schema
            .object_definitions
            .iter()
            .find(|definition| definition.type_name == "common.SecureModeConfig")
            .expect("secure mode definition");
        assert!(secure_mode_definition
            .fields
            .iter()
            .any(|field| field.field_name == "local_private_key"));

        let acl = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "acl")
            .expect("acl field");
        assert!(acl.children.iter().any(|field| field.field_name == "acl_v1"));

        let networking_method = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "networking_method")
            .expect("networking_method field");
        assert!(networking_method
            .enum_options
            .iter()
            .any(|option| option.label == "PublicServer"));
        let networking_method_definition = schema
            .enum_definitions
            .iter()
            .find(|definition| definition.enum_name == "api.manage.NetworkingMethod")
            .expect("networking method enum definition");
        assert!(networking_method_definition
            .options
            .iter()
            .any(|option| option.label == "PublicServer"));

        let data_compress_algo = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "data_compress_algo")
            .expect("data_compress_algo field");
        assert!(data_compress_algo
            .enum_options
            .iter()
            .any(|option| option.label == "Zstd"));
    }

}
