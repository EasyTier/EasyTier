/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Luis Liu. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::Command;
use anyhow::{anyhow, Result};
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Output};
use std::str::FromStr;

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
        if uid == 0 {
            true
        } else {
            false
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
        let pkexec = PathBuf::from_str("/bin/pkexec")?;
        let mut command = StdCommand::new(pkexec);
        let display = env::var("DISPLAY");
        let xauthority = env::var("XAUTHORITY");
        let home = env::var("HOME");

        command.arg("--disable-internal-agent");
        if display.is_ok() || xauthority.is_ok() || home.is_ok() {
            command.arg("env");
            if let Ok(display) = display {
                command.arg(format!("DISPLAY={}", display));
            }
            if let Ok(xauthority) = xauthority {
                command.arg(format!("XAUTHORITY={}", xauthority));
            }
            if let Ok(home) = home {
                command.arg(format!("HOME={}", home));
            }
        } else {
            if self.cmd.get_envs().any(|(_, v)| v.is_some()) {
                command.arg("env");
            }
        }
        for (k, v) in self.cmd.get_envs() {
            if let Some(value) = v {
                command.arg(format!(
                    "{}={}",
                    k.to_str().ok_or(anyhow!("invalid key"))?,
                    value.to_str().ok_or(anyhow!("invalid value"))?
                ));
            }
        }

        command.arg(self.cmd.get_program());
        let args: Vec<&OsStr> = self.cmd.get_args().collect();
        if !args.is_empty() {
            command.args(args);
        }

        let output = command.output()?;
        Ok(output)
    }
}
