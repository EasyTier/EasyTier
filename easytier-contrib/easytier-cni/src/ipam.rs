use std::{
    io,
    net::Ipv4Addr,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, ensure};

use crate::cni::{CniArgs, CniResult, PluginConfig};

fn find_plugin(name: &str, paths: &[PathBuf]) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/') && !name.contains('\\'),
        "invalid IPAM plugin type {name:?}"
    );
    paths
        .iter()
        .map(|path| path.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("IPAM plugin {name:?} was not found in CNI_PATH"))
}

pub(crate) fn run_ipam(
    config: &PluginConfig,
    input: &[u8],
    args: &CniArgs,
    command: &str,
) -> Result<Vec<u8>> {
    let plugin = find_plugin(&config.ipam.plugin_type, &args.path)?;
    let mut child = Command::new(&plugin)
        .env("CNI_COMMAND", command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute IPAM plugin {}", plugin.display()))?;
    io::Write::write_all(child.stdin.as_mut().unwrap(), input)?;
    let output = child.wait_with_output()?;
    if !output.stderr.is_empty() {
        let _ = io::Write::write_all(&mut io::stderr(), &output.stderr);
    }
    ensure!(
        output.status.success(),
        "IPAM plugin {} failed with {}; stdout: {}; stderr: {}",
        config.ipam.plugin_type,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

pub(crate) fn select_ipv4(result: &mut CniResult) -> Result<(Ipv4Addr, u8)> {
    ensure!(
        result.ips.len() == 1,
        "IPAM must return exactly one address"
    );
    ensure!(
        result.routes.is_empty(),
        "routes returned by IPAM are not supported"
    );
    let (address, prefix) = result.ips[0]
        .address
        .split_once('/')
        .context("IPAM address must include a prefix length")?;
    let address: Ipv4Addr = address
        .parse()
        .context("IPAM must return an IPv4 address")?;
    let prefix: u8 = prefix.parse().context("invalid IPv4 prefix length")?;
    ensure!(prefix <= 32, "invalid IPv4 prefix length {prefix}");
    result.ips[0].interface = Some(0);
    Ok((address, prefix))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::cni::CniArgs;

    #[test]
    fn selects_one_ipv4_address() {
        let mut result: CniResult = serde_json::from_value(json!({
            "cniVersion": "1.0.0",
            "ips": [{"address": "10.200.0.8/24"}]
        }))
        .unwrap();
        assert_eq!(
            select_ipv4(&mut result).unwrap(),
            (Ipv4Addr::new(10, 200, 0, 8), 24)
        );
        assert_eq!(result.ips[0].interface, Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn includes_ipam_stderr_in_failures() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let plugin = directory.path().join("failed-ipam");
        fs::write(
            &plugin,
            "#!/bin/sh\necho standard-output\necho useful-diagnostic >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
        let config: PluginConfig = serde_json::from_value(json!({
            "cniVersion": "1.0.0",
            "name": "overlay",
            "networkName": "cluster",
            "networkSecretFile": "/etc/easytier/secret",
            "peers": ["tcp://192.0.2.1:11010"],
            "ipam": {"type": "failed-ipam"}
        }))
        .unwrap();
        let args = CniArgs {
            command: "ADD".to_string(),
            container_id: Some("container".to_string()),
            netns: Some("/proc/1/ns/net".to_string()),
            ifname: Some("net1".to_string()),
            path: vec![directory.path().to_path_buf()],
        };

        let error = run_ipam(&config, b"{}", &args, "ADD").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("standard-output"));
        assert!(message.contains("useful-diagnostic"));
    }
}
