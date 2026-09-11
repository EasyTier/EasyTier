use std::{collections::HashMap, io, net::SocketAddr};

#[cfg(test)]
use std::str::FromStr;

use url::Url;
use xmltree::Element;

use super::errors::{AddAnyPortError, AddPortError, RemovePortError, RequestError, SearchError};
#[cfg(test)]
use super::{
    PortMappingEntry, PortMappingProtocol,
    errors::{GetExternalIpError, GetGenericPortMappingEntryError},
};

pub(super) fn parse_search_result(text: &str) -> Result<(SocketAddr, String), SearchError> {
    for line in text.lines().map(str::trim) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("location") {
            continue;
        }

        let url = Url::parse(value.trim()).map_err(|_| SearchError::InvalidResponse)?;
        let host = url.host_str().ok_or(SearchError::InvalidResponse)?;
        let ip = host.parse().map_err(|_| SearchError::InvalidResponse)?;
        let port = url
            .port_or_known_default()
            .ok_or(SearchError::InvalidResponse)?;
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        return Ok((SocketAddr::new(ip, port), path));
    }
    Err(SearchError::InvalidResponse)
}

pub(super) fn parse_control_urls<R>(response: R) -> Result<(String, String, String), SearchError>
where
    R: io::Read,
{
    let root = Element::parse(response)?;
    root.children
        .iter()
        .filter_map(|child| child.as_element())
        .find(|child| child.name == "device")
        .and_then(parse_device)
        .ok_or(SearchError::InvalidResponse)
}

fn parse_device(device: &Element) -> Option<(String, String, String)> {
    let service = device.get_child("serviceList").and_then(|list| {
        list.children
            .iter()
            .filter_map(|child| child.as_element())
            .filter(|child| child.name == "service")
            .find_map(parse_service)
    });
    service.or_else(|| {
        device.get_child("deviceList").and_then(|list| {
            list.children
                .iter()
                .filter_map(|child| child.as_element())
                .filter(|child| child.name == "device")
                .find_map(parse_device)
        })
    })
}

fn parse_service(service: &Element) -> Option<(String, String, String)> {
    let service_type = service.get_child("serviceType")?.get_text()?.into_owned();
    if ![
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
    ]
    .contains(&service_type.as_str())
    {
        return None;
    }

    let schema_url = service.get_child("SCPDURL")?.get_text()?.into_owned();
    let control_url = service.get_child("controlURL")?.get_text()?.into_owned();
    Some((service_type, schema_url, control_url))
}

pub(super) fn parse_schemas<R>(response: R) -> Result<HashMap<String, Vec<String>>, SearchError>
where
    R: io::Read,
{
    let root = Element::parse(response)?;
    root.children
        .iter()
        .filter_map(|child| child.as_element())
        .find(|child| child.name == "actionList")
        .map(parse_action_list)
        .ok_or(SearchError::InvalidResponse)
}

fn parse_action_list(action_list: &Element) -> HashMap<String, Vec<String>> {
    action_list
        .children
        .iter()
        .filter_map(|child| child.as_element())
        .filter(|child| child.name == "action")
        .filter_map(parse_action)
        .collect()
}

fn parse_action(action: &Element) -> Option<(String, Vec<String>)> {
    let name = action.get_child("name")?.get_text()?.into_owned();
    let arguments = action
        .get_child("argumentList")?
        .children
        .iter()
        .filter_map(|child| child.as_element())
        .filter(|child| child.name == "argument")
        .filter_map(parse_input_argument)
        .collect();
    Some((name, arguments))
}

fn parse_input_argument(argument: &Element) -> Option<String> {
    if argument.get_child("direction")?.get_text()?.as_ref() != "in" {
        return None;
    }
    argument
        .get_child("name")?
        .get_text()
        .map(|name| name.into_owned())
}

pub(super) struct RequestResponse {
    text: String,
    xml: Element,
}

pub(super) type RequestResult = Result<RequestResponse, RequestError>;

pub(super) fn parse_response(text: String, expected: &str) -> RequestResult {
    let mut xml =
        Element::parse(text.as_bytes()).map_err(|_| RequestError::InvalidResponse(text.clone()))?;
    let body = xml
        .get_mut_child("Body")
        .ok_or_else(|| RequestError::InvalidResponse(text.clone()))?;
    if let Some(response) = body.take_child(expected) {
        return Ok(RequestResponse {
            text,
            xml: response,
        });
    }

    let upnp_error = body
        .get_child("Fault")
        .and_then(|fault| fault.get_child("detail"))
        .and_then(|detail| detail.get_child("UPnPError"))
        .ok_or_else(|| RequestError::InvalidResponse(text.clone()))?;
    let code = upnp_error
        .get_child("errorCode")
        .and_then(Element::get_text)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| RequestError::InvalidResponse(text.clone()))?;
    let description = upnp_error
        .get_child("errorDescription")
        .and_then(Element::get_text)
        .map(|value| value.into_owned())
        .ok_or_else(|| RequestError::InvalidResponse(text.clone()))?;
    Err(RequestError::ErrorCode(code, description))
}

#[cfg(test)]
pub(super) fn parse_get_external_ip_response(
    result: RequestResult,
) -> Result<std::net::IpAddr, GetExternalIpError> {
    match result {
        Ok(response) => response
            .xml
            .get_child("NewExternalIPAddress")
            .and_then(Element::get_text)
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| {
                GetExternalIpError::RequestError(RequestError::InvalidResponse(response.text))
            }),
        Err(RequestError::ErrorCode(606, _)) => Err(GetExternalIpError::ActionNotAuthorized),
        Err(error) => Err(GetExternalIpError::RequestError(error)),
    }
}

pub(super) fn parse_add_any_port_mapping_response(
    result: RequestResult,
) -> Result<u16, AddAnyPortError> {
    match result {
        Ok(response) => response
            .xml
            .get_child("NewReservedPort")
            .and_then(Element::get_text)
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| {
                AddAnyPortError::RequestError(RequestError::InvalidResponse(response.text))
            }),
        Err(error) => Err(match error {
            RequestError::ErrorCode(605, _) => AddAnyPortError::DescriptionTooLong,
            RequestError::ErrorCode(606, _) => AddAnyPortError::ActionNotAuthorized,
            RequestError::ErrorCode(728, _) => AddAnyPortError::NoPortsAvailable,
            other => AddAnyPortError::RequestError(other),
        }),
    }
}

pub(super) fn convert_add_random_port_mapping_error(
    error: RequestError,
) -> Option<AddAnyPortError> {
    match error {
        RequestError::ErrorCode(724, _) => None,
        RequestError::ErrorCode(605, _) => Some(AddAnyPortError::DescriptionTooLong),
        RequestError::ErrorCode(606, _) => Some(AddAnyPortError::ActionNotAuthorized),
        RequestError::ErrorCode(718, _) => Some(AddAnyPortError::NoPortsAvailable),
        RequestError::ErrorCode(725, _) => Some(AddAnyPortError::OnlyPermanentLeasesSupported),
        other => Some(AddAnyPortError::RequestError(other)),
    }
}

pub(super) fn convert_add_same_port_mapping_error(error: RequestError) -> AddAnyPortError {
    match error {
        RequestError::ErrorCode(606, _) => AddAnyPortError::ActionNotAuthorized,
        RequestError::ErrorCode(718, _) => AddAnyPortError::ExternalPortInUse,
        RequestError::ErrorCode(725, _) => AddAnyPortError::OnlyPermanentLeasesSupported,
        other => AddAnyPortError::RequestError(other),
    }
}

pub(super) fn convert_add_port_error(error: RequestError) -> AddPortError {
    match error {
        RequestError::ErrorCode(605, _) => AddPortError::DescriptionTooLong,
        RequestError::ErrorCode(606, _) => AddPortError::ActionNotAuthorized,
        RequestError::ErrorCode(718, _) => AddPortError::PortInUse,
        RequestError::ErrorCode(724, _) => AddPortError::SamePortValuesRequired,
        RequestError::ErrorCode(725, _) => AddPortError::OnlyPermanentLeasesSupported,
        other => AddPortError::RequestError(other),
    }
}

pub(super) fn parse_delete_port_mapping_response(
    result: RequestResult,
) -> Result<(), RemovePortError> {
    match result {
        Ok(_) => Ok(()),
        Err(RequestError::ErrorCode(606, _)) => Err(RemovePortError::ActionNotAuthorized),
        Err(RequestError::ErrorCode(714, _)) => Err(RemovePortError::NoSuchPortMapping),
        Err(error) => Err(RemovePortError::RequestError(error)),
    }
}

#[cfg(test)]
pub(super) fn parse_get_generic_port_mapping_entry(
    result: RequestResult,
) -> Result<PortMappingEntry, GetGenericPortMappingEntryError> {
    let response = result?;
    let xml = response.xml;
    let invalid = |message: String| {
        GetGenericPortMappingEntryError::RequestError(RequestError::InvalidResponse(message))
    };
    let field = |name: &str| {
        xml.get_child(name)
            .ok_or_else(|| invalid(format!("{name} is missing")))
    };
    field("NewRemoteHost")?;
    let external_port = parse_number(&xml, "NewExternalPort")?;
    let protocol = match field("NewProtocol")?.get_text().as_deref() {
        Some("UDP") => PortMappingProtocol::Udp,
        Some("TCP") => PortMappingProtocol::Tcp,
        _ => return Err(invalid("NewProtocol is invalid".to_owned())),
    };
    let internal_port = parse_number(&xml, "NewInternalPort")?;
    let internal_client = field("NewInternalClient")?
        .get_text()
        .map(|text| text.into_owned())
        .ok_or_else(|| invalid("NewInternalClient is empty".to_owned()))?;
    match parse_number::<u16>(&xml, "NewEnabled")? {
        0 | 1 => {}
        _ => return Err(invalid("NewEnabled is invalid".to_owned())),
    }
    let port_mapping_description = field("NewPortMappingDescription")?
        .get_text()
        .map(|text| text.into_owned())
        .unwrap_or_default();
    parse_number::<u32>(&xml, "NewLeaseDuration")?;

    Ok(PortMappingEntry {
        external_port,
        protocol,
        internal_port,
        internal_client,
        port_mapping_description,
    })
}

#[cfg(test)]
fn parse_number<T: FromStr>(
    xml: &Element,
    name: &str,
) -> Result<T, GetGenericPortMappingEntryError> {
    xml.get_child(name)
        .and_then(Element::get_text)
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| {
            GetGenericPortMappingEntryError::RequestError(RequestError::InvalidResponse(format!(
                "{name} is missing or invalid"
            )))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_location_is_case_insensitive_and_keeps_query() {
        let (address, path) = parse_search_result(
            "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5431/root.xml?v=2\r\n",
        )
        .unwrap();
        assert_eq!(address, "192.168.1.1:5431".parse().unwrap());
        assert_eq!(path, "/root.xml?v=2");
    }

    #[test]
    fn nested_ppp_service_is_discovered() {
        let description = r#"
            <root><device><deviceList><device><deviceList><device><serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <controlURL>/control</controlURL>
                <SCPDURL>/schema.xml</SCPDURL>
              </service>
            </serviceList></device></deviceList></device></deviceList></device></root>
        "#;
        assert_eq!(
            parse_control_urls(description.as_bytes()).unwrap(),
            (
                "urn:schemas-upnp-org:service:WANPPPConnection:1".to_owned(),
                "/schema.xml".to_owned(),
                "/control".to_owned(),
            )
        );
    }

    #[test]
    fn device_description_uses_declared_xml_encoding() {
        let description = r#"<?xml version="1.0" encoding="UTF-16"?>
            <root><device><serviceList><service>
              <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
              <controlURL>/control</controlURL>
              <SCPDURL>/schema.xml</SCPDURL>
            </service></serviceList></device></root>"#;
        let mut encoded = vec![0xff, 0xfe];
        for code_unit in description.encode_utf16() {
            encoded.extend_from_slice(&code_unit.to_le_bytes());
        }

        assert_eq!(
            parse_control_urls(encoded.as_slice()).unwrap(),
            (
                "urn:schemas-upnp-org:service:WANIPConnection:1".to_owned(),
                "/schema.xml".to_owned(),
                "/control".to_owned(),
            )
        );
    }

    #[test]
    fn schema_contains_only_input_arguments() {
        let schema = r#"
            <scpd><actionList><action><name>AddPortMapping</name><argumentList>
              <argument><name>NewExternalPort</name><direction>in</direction></argument>
              <argument><name>Result</name><direction>out</direction></argument>
              <argument><name>NewProtocol</name><direction>in</direction></argument>
            </argumentList></action></actionList></scpd>
        "#;
        assert_eq!(
            parse_schemas(schema.as_bytes()).unwrap()["AddPortMapping"],
            ["NewExternalPort", "NewProtocol"]
        );
    }

    #[test]
    fn soap_fault_preserves_error_code() {
        let response = r#"
            <Envelope><Body><Fault><detail><UPnPError>
              <errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
            </UPnPError></detail></Fault></Body></Envelope>
        "#;
        assert!(matches!(
            parse_response(response.to_owned(), "GetGenericPortMappingEntryResponse"),
            Err(RequestError::ErrorCode(713, _))
        ));
    }
}
