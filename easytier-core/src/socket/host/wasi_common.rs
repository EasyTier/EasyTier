use std::io;

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
