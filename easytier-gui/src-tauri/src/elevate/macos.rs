/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Luis Liu. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Thanks to https://github.com/jorangreef/sudo-prompt/blob/master/index.js
// MIT License
//
// Copyright (c) 2015 Joran Dirk Greef
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// ...
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::Command;
use anyhow::Result;
use std::env;
use std::path::PathBuf;
use std::process::{ExitStatus, Output};

use std::ffi::{CString, OsString};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use libc::{fcntl, fileno, waitpid, EINTR, F_GETOWN};
use security_framework_sys::authorization::{
    errAuthorizationSuccess, kAuthorizationFlagDefaults, kAuthorizationFlagDestroyRights,
    AuthorizationCreate, AuthorizationExecuteWithPrivileges, AuthorizationFree, AuthorizationRef,
};

const ENV_PATH: &str = "PATH";

fn get_exe_path<P: AsRef<Path>>(exe_name: P) -> Option<PathBuf> {
    let exe_name = exe_name.as_ref();
    if exe_name.has_root() {
        return Some(exe_name.into());
    }

    if let Ok(abs_path) = exe_name.canonicalize() {
        if abs_path.is_file() {
            return Some(abs_path);
        }
    }

    env::var_os(ENV_PATH).and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

macro_rules! make_cstring {
    ($s:expr) => {
        match CString::new($s.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::Other, "null byte in string"));
            }
        }
    };
}

/// The implementation of state check and elevated executing varies on each platform
impl Command {
    /// Check the state the current program running
    ///
    /// Return `true` if the program is running as root, otherwise false
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use elevated_command::Command;
    ///
    /// fn main() {
    ///     let is_elevated = Command::is_elevated();
    ///
    /// }
    /// ```
    pub fn is_elevated() -> bool {
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };

        match (uid, euid) {
            (0, 0) => true,
            (_, 0) => true,
            (_, _) => false,
        }
    }

    /// Prompting the user with a graphical OS dialog for the root password,
    /// excuting the command with escalated privileges, and return the output
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use elevated_command::Command;
    /// use std::process::Command as StdCommand;
    ///
    /// fn main() {
    ///     let mut cmd = StdCommand::new("path to the application");
    ///     let elevated_cmd = Command::new(cmd);
    ///     let output = elevated_cmd.output().unwrap();
    /// }
    /// ```
    pub fn output(&self) -> Result<Output> {
        let (_prog_owned, _args_owned, prog, argv) = self.prepare_runas()?;
        let status = unsafe { gui_runas(prog, argv.as_ptr(), true) };
        Ok(Output {
            status: unsafe { mem::transmute(status) },
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    pub fn spawn(&self) -> Result<()> {
        let (_prog_owned, _args_owned, prog, argv) = self.prepare_runas()?;
        let status = unsafe { gui_runas(prog, argv.as_ptr(), false) };
        if status < 0 {
            return Err(anyhow::anyhow!("Failed to spawn elevated process"));
        }
        Ok(())
    }

    fn prepare_runas(&self) -> io::Result<(CString, Vec<CString>, *const i8, Vec<*const i8>)> {
        let exe: OsString = match get_exe_path(&self.cmd.get_program()) {
            Some(exe) => exe.into(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "executable not found",
                ));
            }
        };
        let prog = make_cstring!(exe);
        let mut args = vec![];
        for arg in self.cmd.get_args() {
            args.push(make_cstring!(arg))
        }
        let mut argv: Vec<_> = args.iter().map(|x| x.as_ptr()).collect();
        argv.push(ptr::null());

        let prog_ptr = prog.as_ptr();
        Ok((prog, args, prog_ptr, argv))
    }
}

unsafe fn gui_runas(prog: *const i8, argv: *const *const i8, wait: bool) -> i32 {
    let mut authref: AuthorizationRef = ptr::null_mut();
    let mut pipe: *mut libc::FILE = ptr::null_mut();

    if AuthorizationCreate(
        ptr::null(),
        ptr::null(),
        kAuthorizationFlagDefaults,
        &mut authref,
    ) != errAuthorizationSuccess
    {
        return -1;
    }
    if AuthorizationExecuteWithPrivileges(
        authref,
        prog,
        kAuthorizationFlagDefaults,
        argv as *const *mut _,
        &mut pipe,
    ) != errAuthorizationSuccess
    {
        AuthorizationFree(authref, kAuthorizationFlagDestroyRights);
        return -1;
    }

    let mut status = 0;
    if wait {
        let pid = fcntl(fileno(pipe), F_GETOWN, 0);
        loop {
            let r = waitpid(pid, &mut status, 0);
            if r == -1 && io::Error::last_os_error().raw_os_error() == Some(EINTR) {
                continue;
            } else {
                break;
            }
        }
    }

    let flag = if wait {
        kAuthorizationFlagDestroyRights
    } else {
        kAuthorizationFlagDefaults
    };
    AuthorizationFree(authref, flag);
    status
}
