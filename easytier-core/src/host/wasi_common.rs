use std::io;

#[cfg(target_os = "wasi")]
pub(super) fn status(operation: &str, result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(host_error(operation, result))
    }
}

pub(super) fn host_error(operation: &str, code: i32) -> io::Error {
    io::Error::other(format!("host {operation} failed with code {code}"))
}

pub(super) fn tcp_connect_error(code: i32) -> io::Error {
    let kind = match code {
        -6 => io::ErrorKind::ConnectionRefused,
        -7 => io::ErrorKind::ConnectionAborted,
        -8 => io::ErrorKind::ConnectionReset,
        -9 => io::ErrorKind::NotConnected,
        _ => return host_error("take_tcp_connect", code),
    };
    io::Error::new(kind, format!("host TCP connect failed with code {code}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_status_preserves_error_kinds() {
        assert_eq!(
            tcp_connect_error(-6).kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            tcp_connect_error(-7).kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(tcp_connect_error(-8).kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(tcp_connect_error(-9).kind(), io::ErrorKind::NotConnected);
        assert_eq!(tcp_connect_error(-3).kind(), io::ErrorKind::Other);
    }
}
