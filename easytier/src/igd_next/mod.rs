// Derived from igd-next 0.17.0 and upstream commit
// bb335d60348386526684d9249d7ae733772279e4, with its network transport
// replaced by EasyTier's socket factories. See LICENSE in this
// directory for the upstream license.

mod errors;
mod messages;
mod parsing;

use std::{collections::HashMap, fmt, net::SocketAddr, time::Duration};

#[cfg(test)]
use std::net::IpAddr;

use bytes::Bytes;
use easytier_core::socket::{
    tcp::TcpConnectOptions,
    udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{
    Method, Request,
    client::conn::http1,
    header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST},
};
use hyper_util::rt::TokioIo;
use rand::Rng as _;
use tokio::time::timeout;

pub(crate) use errors::AddAnyPortError;
#[cfg(test)]
use errors::GetExternalIpError;
#[cfg(test)]
pub(crate) use errors::GetGenericPortMappingEntryError;
use errors::{AddPortError, HttpTransportError, RemovePortError, RequestError, SearchError};

use crate::socket::{tcp::connect_tcp, udp::RuntimeUdpSocketFactory};

const DEFAULT_SEARCH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SSDP_RESPONSE_SIZE: usize = 1500;
const MAX_HTTP_RESPONSE_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortMappingProtocol {
    #[cfg(test)]
    Tcp,
    Udp,
}

impl fmt::Display for PortMappingProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            #[cfg(test)]
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

pub(crate) struct SearchOptions {
    pub(crate) bind_addr: SocketAddr,
    pub(crate) broadcast_address: SocketAddr,
    pub(crate) timeout: Option<Duration>,
    pub(crate) single_search_timeout: Option<Duration>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            broadcast_address: "239.255.255.250:1900".parse().unwrap(),
            timeout: Some(DEFAULT_SEARCH_TIMEOUT),
            single_search_timeout: Some(DEFAULT_RESPONSE_TIMEOUT),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Gateway {
    pub(crate) addr: SocketAddr,
    control_url: String,
    control_schema: HashMap<String, Vec<String>>,
    service_type: String,
}

#[cfg(test)]
pub(crate) struct PortMappingEntry {
    pub(crate) external_port: u16,
    pub(crate) protocol: PortMappingProtocol,
    pub(crate) internal_port: u16,
    pub(crate) internal_client: String,
    pub(crate) port_mapping_description: String,
}

pub(crate) async fn search_gateway(options: SearchOptions) -> Result<Gateway, SearchError> {
    let search_timeout = options.timeout.unwrap_or(DEFAULT_SEARCH_TIMEOUT);
    timeout(search_timeout, search_gateway_inner(options))
        .await
        .map_err(|_| SearchError::NoResponseWithinTimeout)?
}

async fn search_gateway_inner(options: SearchOptions) -> Result<Gateway, SearchError> {
    let bind_options = UdpBindOptions::direct_connect().with_local_addr(Some(options.bind_addr));
    let socket = RuntimeUdpSocketFactory::new()
        .bind_udp(bind_options)
        .await
        .map_err(|error| SearchError::Io(std::io::Error::other(error.to_string())))?;
    socket
        .send_to(
            messages::SEARCH_REQUEST.as_bytes(),
            options.broadcast_address,
        )
        .await?;

    let response_timeout = options
        .single_search_timeout
        .unwrap_or(DEFAULT_RESPONSE_TIMEOUT);
    loop {
        let mut buffer = [0_u8; MAX_SSDP_RESPONSE_SIZE];
        let (length, from) = match timeout(response_timeout, socket.recv_from(&mut buffer)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                tracing::debug!(?error, "failed to receive IGD discovery response");
                continue;
            }
            Err(_) => {
                tracing::debug!("timed out waiting for IGD discovery response");
                continue;
            }
        };
        let response = match std::str::from_utf8(&buffer[..length]) {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(?error, %from, "invalid IGD discovery response encoding");
                continue;
            }
        };
        let (addr, root_url) = match parsing::parse_search_result(response) {
            Ok(result) => result,
            Err(error) => {
                tracing::debug!(?error, %from, "invalid IGD discovery response");
                continue;
            }
        };
        let (service_type, schema_url, control_url) = match get_control_urls(addr, &root_url).await
        {
            Ok(urls) => urls,
            Err(error) => {
                tracing::debug!(?error, %addr, "failed to read IGD device description");
                continue;
            }
        };
        let control_schema = match get_control_schema(addr, &schema_url).await {
            Ok(schema) => schema,
            Err(error) => {
                tracing::debug!(?error, %addr, "failed to read IGD control schema");
                continue;
            }
        };
        return Ok(Gateway {
            addr,
            control_url,
            control_schema,
            service_type,
        });
    }
}

async fn get_control_urls(
    addr: SocketAddr,
    root_url: &str,
) -> Result<(String, String, String), SearchError> {
    let response = send_http_request(addr, root_url, Method::GET, None, String::new()).await?;
    parsing::parse_control_urls(response.as_ref())
}

async fn get_control_schema(
    addr: SocketAddr,
    schema_url: &str,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let response = send_http_request(addr, schema_url, Method::GET, None, String::new()).await?;
    parsing::parse_schemas(response.as_ref())
}

async fn send_http_request(
    addr: SocketAddr,
    path: &str,
    method: Method,
    soap_action: Option<&str>,
    body: String,
) -> Result<Bytes, HttpTransportError> {
    timeout(
        DEFAULT_REQUEST_TIMEOUT,
        send_http_request_inner(addr, path, method, soap_action, body),
    )
    .await
    .map_err(|_| HttpTransportError::TimedOut)?
}

async fn send_http_request_inner(
    addr: SocketAddr,
    path: &str,
    method: Method,
    soap_action: Option<&str>,
    body: String,
) -> Result<Bytes, HttpTransportError> {
    let stream = connect_tcp(TcpConnectOptions::direct_connect(addr)).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    let body = Bytes::from(body);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, addr.to_string())
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, body.len() as u64);
    if let Some(action) = soap_action {
        request = request
            .header("SOAPAction", action)
            .header(CONTENT_TYPE, "text/xml; charset=utf-8");
    }
    let request = request.body(Full::new(body))?;

    let response = async move {
        let response = sender.send_request(request).await?;
        let body = Limited::new(response.into_body(), MAX_HTTP_RESPONSE_SIZE)
            .collect()
            .await
            .map_err(|error| HttpTransportError::InvalidResponse(error.to_string()))?
            .to_bytes();
        Ok::<_, HttpTransportError>(body)
    };
    tokio::pin!(response);
    tokio::pin!(connection);
    tokio::select! {
        biased;
        result = &mut response => result,
        result = &mut connection => {
            result?;
            response.await
        }
    }
}

impl Gateway {
    async fn perform_request(
        &self,
        action: &str,
        body: &str,
        expected_response: &str,
    ) -> parsing::RequestResult {
        let soap_action = messages::soap_action(&self.service_type, action);
        let response = send_http_request(
            self.addr,
            &self.control_url,
            Method::POST,
            Some(&soap_action),
            body.to_owned(),
        )
        .await?;
        let response = String::from_utf8(response.to_vec()).map_err(HttpTransportError::from)?;
        parsing::parse_response(response, expected_response)
    }

    #[cfg(test)]
    pub(crate) async fn get_external_ip(&self) -> Result<IpAddr, GetExternalIpError> {
        let result = self
            .perform_request(
                messages::GET_EXTERNAL_IP_ACTION,
                &messages::format_get_external_ip_message(&self.service_type),
                "GetExternalIPAddressResponse",
            )
            .await;
        parsing::parse_get_external_ip_response(result)
    }

    pub(crate) async fn add_any_port(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        if local_addr.port() == 0 {
            return Err(AddAnyPortError::InternalPortZeroInvalid);
        }

        if let Some(schema) = self
            .control_schema
            .get(messages::ADD_ANY_PORT_MAPPING_ACTION)
        {
            let external_port = random_port();
            let result = self
                .perform_request(
                    messages::ADD_ANY_PORT_MAPPING_ACTION,
                    &messages::format_add_any_port_mapping_message(
                        &self.service_type,
                        schema,
                        protocol,
                        external_port,
                        local_addr,
                        lease_duration,
                        description,
                    ),
                    "AddAnyPortMappingResponse",
                )
                .await;
            return parsing::parse_add_any_port_mapping_response(result);
        }

        self.retry_add_random_port_mapping(protocol, local_addr, lease_duration, description)
            .await
    }

    async fn retry_add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        for _ in 0..20 {
            match self
                .add_random_port_mapping(protocol, local_addr, lease_duration, description)
                .await
            {
                Err(AddAnyPortError::NoPortsAvailable) => continue,
                result => return result,
            }
        }
        Err(AddAnyPortError::NoPortsAvailable)
    }

    async fn add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        let external_port = random_port();
        match self
            .add_port_mapping(
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            )
            .await
        {
            Ok(()) => Ok(external_port),
            Err(error) => match parsing::convert_add_random_port_mapping_error(error) {
                Some(error) => Err(error),
                None => {
                    self.add_same_port_mapping(protocol, local_addr, lease_duration, description)
                        .await
                }
            },
        }
    }

    async fn add_same_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        self.add_port_mapping(
            protocol,
            local_addr.port(),
            local_addr,
            lease_duration,
            description,
        )
        .await
        .map(|()| local_addr.port())
        .map_err(parsing::convert_add_same_port_mapping_error)
    }

    async fn add_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), RequestError> {
        let schema = self
            .control_schema
            .get(messages::ADD_PORT_MAPPING_ACTION)
            .ok_or_else(|| {
                RequestError::UnsupportedAction(messages::ADD_PORT_MAPPING_ACTION.to_owned())
            })?;
        self.perform_request(
            messages::ADD_PORT_MAPPING_ACTION,
            &messages::format_add_port_mapping_message(
                &self.service_type,
                schema,
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            ),
            "AddPortMappingResponse",
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError> {
        if external_port == 0 {
            return Err(AddPortError::ExternalPortZeroInvalid);
        }
        if local_addr.port() == 0 {
            return Err(AddPortError::InternalPortZeroInvalid);
        }
        self.add_port_mapping(
            protocol,
            external_port,
            local_addr,
            lease_duration,
            description,
        )
        .await
        .map_err(parsing::convert_add_port_error)
    }

    pub(crate) async fn remove_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
    ) -> Result<(), RemovePortError> {
        let schema = self
            .control_schema
            .get(messages::DELETE_PORT_MAPPING_ACTION)
            .ok_or_else(|| {
                RemovePortError::RequestError(RequestError::UnsupportedAction(
                    messages::DELETE_PORT_MAPPING_ACTION.to_owned(),
                ))
            })?;
        let result = self
            .perform_request(
                messages::DELETE_PORT_MAPPING_ACTION,
                &messages::format_delete_port_message(
                    &self.service_type,
                    schema,
                    protocol,
                    external_port,
                ),
                "DeletePortMappingResponse",
            )
            .await;
        parsing::parse_delete_port_mapping_response(result)
    }

    #[cfg(test)]
    pub(crate) async fn get_generic_port_mapping_entry(
        &self,
        index: u32,
    ) -> Result<PortMappingEntry, GetGenericPortMappingEntryError> {
        let result = self
            .perform_request(
                messages::GET_GENERIC_PORT_MAPPING_ENTRY_ACTION,
                &messages::format_get_generic_port_mapping_entry_message(&self.service_type, index),
                "GetGenericPortMappingEntryResponse",
            )
            .await;
        parsing::parse_get_generic_port_mapping_entry(result)
    }
}

fn random_port() -> u16 {
    rand::thread_rng().gen_range(32_768..65_535)
}
