use std::net::SocketAddr;

use super::PortMappingProtocol;

pub(super) const SEARCH_REQUEST: &str = "M-SEARCH * HTTP/1.1\r
Host:239.255.255.250:1900\r
ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
Man:\"ssdp:discover\"\r
MX:3\r\n\r\n";

#[cfg(test)]
pub(super) const GET_EXTERNAL_IP_ACTION: &str = "GetExternalIPAddress";
pub(super) const ADD_ANY_PORT_MAPPING_ACTION: &str = "AddAnyPortMapping";
pub(super) const ADD_PORT_MAPPING_ACTION: &str = "AddPortMapping";
pub(super) const DELETE_PORT_MAPPING_ACTION: &str = "DeletePortMapping";
#[cfg(test)]
pub(super) const GET_GENERIC_PORT_MAPPING_ENTRY_ACTION: &str = "GetGenericPortMappingEntry";

const MESSAGE_HEAD: &str = r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>"#;
const MESSAGE_TAIL: &str = r#"</s:Body>
</s:Envelope>"#;

pub(super) fn soap_action(service_type: &str, action: &str) -> String {
    format!("\"{service_type}#{action}\"")
}

fn format_message(body: String) -> String {
    format!("{MESSAGE_HEAD}{body}{MESSAGE_TAIL}")
}

fn xml_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

#[cfg(test)]
pub(super) fn format_get_external_ip_message(service_type: &str) -> String {
    format_message(format!(
        r#"<m:GetExternalIPAddress xmlns:m="{service_type}">
        </m:GetExternalIPAddress>"#
    ))
}

pub(super) fn format_add_any_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let arguments = format_mapping_arguments(
        schema,
        protocol,
        external_port,
        local_addr,
        lease_duration,
        description,
    );
    format_message(format!(
        r#"<u:AddAnyPortMapping xmlns:u="{service_type}">
        {arguments}
        </u:AddAnyPortMapping>"#
    ))
}

pub(super) fn format_add_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let arguments = format_mapping_arguments(
        schema,
        protocol,
        external_port,
        local_addr,
        lease_duration,
        description,
    );
    format_message(format!(
        r#"<u:AddPortMapping xmlns:u="{service_type}">
        {arguments}
        </u:AddPortMapping>"#
    ))
}

fn format_mapping_arguments(
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewEnabled" => "1".to_owned(),
                "NewExternalPort" => external_port.to_string(),
                "NewInternalClient" => local_addr.ip().to_string(),
                "NewInternalPort" => local_addr.port().to_string(),
                "NewLeaseDuration" => lease_duration.to_string(),
                "NewPortMappingDescription" => description.to_owned(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => String::new(),
                unknown => {
                    tracing::warn!(argument = unknown, "unknown IGD SOAP argument");
                    return None;
                }
            };
            Some(format!("<{argument}>{}</{argument}>", xml_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn format_delete_port_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
) -> String {
    let arguments = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewExternalPort" => external_port.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => String::new(),
                unknown => {
                    tracing::warn!(argument = unknown, "unknown IGD SOAP argument");
                    return None;
                }
            };
            Some(format!("<{argument}>{}</{argument}>", xml_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:DeletePortMapping xmlns:u="{service_type}">
        {arguments}
        </u:DeletePortMapping>"#
    ))
}

#[cfg(test)]
pub(super) fn format_get_generic_port_mapping_entry_message(
    service_type: &str,
    port_mapping_index: u32,
) -> String {
    format_message(format!(
        r#"<u:GetGenericPortMappingEntry xmlns:u="{service_type}">
        <NewPortMappingIndex>{port_mapping_index}</NewPortMappingIndex>
        </u:GetGenericPortMappingEntry>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PPP_SERVICE: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

    #[test]
    fn soap_action_and_body_use_discovered_service_type() {
        assert_eq!(
            soap_action(PPP_SERVICE, ADD_PORT_MAPPING_ACTION),
            "\"urn:schemas-upnp-org:service:WANPPPConnection:1#AddPortMapping\""
        );

        let body = format_add_port_mapping_message(
            PPP_SERVICE,
            &["NewProtocol".to_owned(), "NewExternalPort".to_owned()],
            PortMappingProtocol::Udp,
            12345,
            "192.168.1.5:80".parse().unwrap(),
            0,
            "test",
        );
        assert!(body.contains(r#"xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1""#));
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("<NewExternalPort>12345</NewExternalPort>"));
    }

    #[test]
    fn mapping_description_is_xml_escaped() {
        let body = format_add_port_mapping_message(
            PPP_SERVICE,
            &["NewPortMappingDescription".to_owned()],
            PortMappingProtocol::Udp,
            12345,
            "192.168.1.5:80".parse().unwrap(),
            0,
            "Bob & Alice </NewPortMappingDescription><evil>",
        );
        assert!(body.contains("Bob &amp; Alice &lt;/NewPortMappingDescription&gt;&lt;evil&gt;"));
        assert!(!body.contains("<evil>"));
    }
}
