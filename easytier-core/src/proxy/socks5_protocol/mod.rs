//! Portable SOCKS5 wire types and codecs.
//!
//! This library is maintained by [anyip.io](https://anyip.io/) a residential and mobile socks5 proxy provider.
//!
//! ## Features
//!
//! - An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
//! - An `async`/`.await` [SOCKS4 Client](https://www.openssh.com/txt/socks4.protocol) implementation.
//! - An `async`/`.await` [SOCKS4a Client](https://www.openssh.com/txt/socks4a.protocol) implementation.
//! - No **unsafe** code
//! - Built on-top of `tokio` library
//! - Ultra lightweight and scalable
//! - No system dependencies
//! - Cross-platform
//! - Authentication methods:
//!   - No-Auth method
//!   - Username/Password auth method
//!   - Custom auth methods can be implemented via the Authentication Trait
//!   - Credentials returned on authentication success
//! - All SOCKS5 RFC errors (replies) should be mapped
//! - `AsyncRead + AsyncWrite` traits are implemented on Socks5Stream & Socks5Socket
//! - `IPv4`, `IPv6`, and `Domains` types are supported
//! - Config helper for Socks5Server
//!
//! DNS resolution, socket creation, listeners, and concrete command execution
//! are deliberately supplied by host adapters outside this module.

#![forbid(unsafe_code)]

pub mod runtime;
pub mod server;
pub mod target_addr;

use anyhow::Context;
use std::fmt;
use std::io;
pub use target_addr::{AddrError, TargetAddr, ToTargetAddr, read_address};
use thiserror::Error;

use tokio::io::AsyncReadExt;

use tracing::error;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq)]
pub enum Socks5Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
}

impl Socks5Command {
    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> Option<Socks5Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT      => Some(Socks5Command::TCPConnect),
            consts::SOCKS5_CMD_TCP_BIND         => Some(Socks5Command::TCPBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE    => Some(Socks5Command::UDPAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> Option<AuthenticationMethod> {
        match code {
            consts::SOCKS5_AUTH_METHOD_NONE     => Some(AuthenticationMethod::None),
            consts::SOCKS5_AUTH_METHOD_PASSWORD => Some(AuthenticationMethod::Password { username: "test".to_string(), password: "test".to_string()}),
            _                                   => None,
        }
    }
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthenticationMethod::None => f.write_str("AuthenticationMethod::None"),
            AuthenticationMethod::Password { .. } => f.write_str("AuthenticationMethod::Password"),
        }
    }
}

//impl Vec<AuthenticationMethod> {
//    pub fn as_bytes(&self) -> &[u8] {
//        self.iter().map(|l| l.as_u8()).collect()
//    }
//}
//
//impl From<&[AuthenticationMethod]> for &[u8] {
//    fn from(_: Vec<AuthenticationMethod>) -> Self {
//        &[0x00]
//    }
//}

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Domain exceeded max sequence length")]
    ExceededMaxDomainLen(usize),
    #[error("Authentication failed `{0}`")]
    AuthenticationFailed(String),
    #[error("Authentication rejected `{0}`")]
    AuthenticationRejected(String),

    #[error("Error with reply: {0}.")]
    ReplyError(#[from] ReplyError),

    //    #[error("Other: `{0}`.")]
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = SocksError> = core::result::Result<T, E>;

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            ReplyError::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            ReplyError::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            ReplyError::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            ReplyError::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            ReplyError::ConnectionTimeout       => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            ReplyError::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }
}

/// Generate UDP header
///
/// # UDP Request header structure.
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
///
/// The fields in the UDP request header are:
///
///     o  RSV  Reserved X'0000'
///     o  FRAG    Current fragment number
///     o  ATYP    address type of following addresses:
///        o  IP V4 address: X'01'
///        o  DOMAINNAME: X'03'
///        o  IP V6 address: X'04'
///     o  DST.ADDR       desired destination address
///     o  DST.PORT       desired destination port
///     o  DATA     user data
/// ```
pub fn new_udp_header<T: ToTargetAddr>(target_addr: T) -> Result<Vec<u8>> {
    let mut header = vec![
        0, 0, // RSV
        0, // FRAG
    ];
    header.append(&mut target_addr.to_target_addr()?.to_be_bytes()?);

    Ok(header)
}

/// Parse data from UDP client on raw buffer, return (frag, target_addr, payload).
pub async fn parse_udp_request(mut req: &[u8]) -> Result<(u8, TargetAddr, &[u8])> {
    let mut rsv = [0u8; 2];
    req.read_exact(&mut rsv)
        .await
        .context("Malformed request")?;

    if !rsv.eq(&[0u8; 2]) {
        return Err(ReplyError::GeneralFailure.into());
    }

    let mut frag_and_type = [0u8; 2];
    req.read_exact(&mut frag_and_type)
        .await
        .context("Malformed request")?;
    let [frag, atyp] = frag_and_type;

    let target_addr = read_address(&mut req, atyp).await.map_err(|e| {
        // print explicit error
        error!("{:#}", e);
        // then convert it to a reply
        ReplyError::AddressTypeNotSupported
    })?;

    Ok((frag, target_addr, req))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[tokio::test]
    async fn udp_ipv4_header_round_trips() {
        let destination: SocketAddr = "10.42.0.7:5353".parse().unwrap();
        let mut packet = new_udp_header(destination).unwrap();
        packet.extend_from_slice(b"payload");

        let (fragment, parsed_destination, payload) = parse_udp_request(&packet).await.unwrap();

        assert_eq!(fragment, 0);
        assert_eq!(parsed_destination, TargetAddr::Ip(destination));
        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn udp_domain_header_round_trips() {
        let mut packet = new_udp_header(("peer.example", 443)).unwrap();
        packet.extend_from_slice(b"hello");

        let (_, parsed_destination, payload) = parse_udp_request(&packet).await.unwrap();

        assert_eq!(
            parsed_destination,
            TargetAddr::Domain("peer.example".to_string(), 443)
        );
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn udp_header_rejects_nonzero_reserved_field() {
        let err = parse_udp_request(&[1, 0, 0, consts::SOCKS5_ADDR_TYPE_IPV4])
            .await
            .err()
            .expect("nonzero reserved field must fail");

        assert!(matches!(
            err,
            SocksError::ReplyError(ReplyError::GeneralFailure)
        ));
    }
}
