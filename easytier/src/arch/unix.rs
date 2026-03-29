use std::io::{Error as IoError, Result as IoResult};
use std::mem;
use std::os::fd::AsRawFd;

use nix::libc;

pub fn set_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> IoResult<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

pub fn set_socket_option_supported(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> IoResult<bool> {
    match set_socket_option(socket, level, name, value) {
        Ok(_) => Ok(true),
        Err(err) => match err.raw_os_error() {
            Some(libc::ENOPROTOOPT) => Ok(false),
            Some(libc::EOPNOTSUPP) => Ok(false),
            _ => Err(err),
        },
    }
}
