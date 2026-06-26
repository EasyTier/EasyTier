use crate::config::types::stored_config::LocalSocketSyncMessage;
use serde::Serialize;
use std::io::{Error, ErrorKind, Write};
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TunRequestPayload {
    pub config_id: String,
    pub instance_id: String,
    pub display_name: String,
    pub virtual_ipv4: Option<String>,
    pub virtual_ipv4_cidr: Option<String>,
    pub aggregated_routes: Vec<String>,
    pub magic_dns_enabled: bool,
    pub need_exit_node: bool,
}

pub(crate) fn send_local_socket_message(
    stream: &mut UnixStream,
    message_type: &str,
    payload_json: String,
) -> std::io::Result<()> {
    let message = LocalSocketSyncMessage {
        message_type: message_type.to_string(),
        payload_json,
    };
    let mut raw = serde_json::to_vec(&message)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
    raw.push(b'\n');
    stream.write_all(&raw)?;
    Ok(())
}

fn shrink_clients_if_sparse(clients: &mut Vec<UnixStream>) {
    let sparse_limit = clients.len().saturating_mul(2).max(4);
    if clients.capacity() > sparse_limit {
        clients.shrink_to_fit();
    }
}

pub(crate) fn broadcast_local_socket_message(
    clients: &mut Vec<UnixStream>,
    message_type: &str,
    payload_json: &str,
) -> bool {
    let mut active_clients = Vec::with_capacity(clients.len());
    let mut delivered = false;
    for mut client in clients.drain(..) {
        if send_local_socket_message(&mut client, message_type, payload_json.to_string()).is_ok() {
            delivered = true;
            active_clients.push(client);
        }
    }
    shrink_clients_if_sparse(&mut active_clients);
    *clients = active_clients;
    delivered
}

pub(crate) fn send_local_socket_json_payload_message(
    stream: &mut UnixStream,
    message_type: &str,
    payload_json: &str,
) -> std::io::Result<()> {
    let message_type_json = serde_json::to_string(message_type)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
    let mut raw = Vec::with_capacity(message_type_json.len() + payload_json.len() + 38);
    raw.extend_from_slice(b"{\"messageType\":");
    raw.extend_from_slice(message_type_json.as_bytes());
    raw.extend_from_slice(b",\"payloadJson\":");
    raw.extend_from_slice(payload_json.as_bytes());
    raw.extend_from_slice(b"}\n");
    stream.write_all(&raw)?;
    Ok(())
}

pub(crate) fn broadcast_local_socket_json_payload_message(
    clients: &mut Vec<UnixStream>,
    message_type: &str,
    payload_json: &str,
) -> bool {
    let mut active_clients = Vec::with_capacity(clients.len());
    let mut delivered = false;
    for mut client in clients.drain(..) {
        if send_local_socket_json_payload_message(&mut client, message_type, payload_json).is_ok() {
            delivered = true;
            active_clients.push(client);
        }
    }
    shrink_clients_if_sparse(&mut active_clients);
    *clients = active_clients;
    delivered
}
