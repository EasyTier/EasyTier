use std::time::Duration;
use tokio::io::ErrorKind as IOErrorKind;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;

use crate::gateway::fast_socks5::{ReplyError, Result};

/// Easy to destructure bytes buffers by naming each fields:
///
/// # Examples (before)
///
/// ```ignore
/// let mut buf = [0u8; 2];
/// stream.read_exact(&mut buf).await?;
/// let [version, method_len] = buf;
///
/// assert_eq!(version, 0x05);
/// ```
///
/// # Examples (after)
///
/// ```ignore
/// let [version, method_len] = read_exact!(stream, [0u8; 2]);
///
/// assert_eq!(version, 0x05);
/// ```
#[macro_export]
macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        //        $stream
        //            .read_exact(&mut x)
        //            .await
        //            .map_err(|_| io_err("lol"))?;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

pub async fn tcp_connect_with_timeout<T>(addr: T, request_timeout_s: u64) -> Result<TcpStream>
where
    T: ToSocketAddrs,
{
    let fut = tcp_connect(addr);
    match timeout(Duration::from_secs(request_timeout_s), fut).await {
        Ok(result) => result,
        Err(_) => Err(ReplyError::ConnectionTimeout.into()),
    }
}

pub async fn tcp_connect<T>(addr: T) -> Result<TcpStream>
where
    T: ToSocketAddrs,
{
    match TcpStream::connect(addr).await {
        Ok(o) => Ok(o),
        Err(e) => match e.kind() {
            // Match other TCP errors with ReplyError
            IOErrorKind::ConnectionRefused => Err(ReplyError::ConnectionRefused.into()),
            IOErrorKind::ConnectionAborted => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::ConnectionReset => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::NotConnected => Err(ReplyError::NetworkUnreachable.into()),
            _ => Err(e.into()), // #[error("General failure")] ?
        },
    }
}
