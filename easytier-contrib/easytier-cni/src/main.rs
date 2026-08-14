mod attachment;
mod cni;
mod commands;
mod ipam;
mod runtime;

use std::io::{self, Read};

use anyhow::Result;
use cni::{PluginConfig, SUPPORTED_VERSIONS, parse_args};
use commands::{add, check, delete};
use serde::Serialize;
use serde_json::{Value, json};

fn read_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    Ok(input)
}

fn print_json(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(io::stdout(), value)?;
    println!();
    Ok(())
}

fn print_error(version: &str, error: &anyhow::Error) {
    let _ = print_json(&json!({
        "cniVersion": version,
        "code": 100,
        "msg": "EasyTier CNI operation failed",
        "details": format!("{error:#}"),
    }));
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_args();
    if args.command == "VERSION" {
        let input = read_stdin().unwrap_or_default();
        let requested = serde_json::from_slice::<Value>(&input)
            .ok()
            .and_then(|value| value.get("cniVersion")?.as_str().map(str::to_string))
            .unwrap_or_else(|| "1.0.0".to_string());
        if let Err(error) = print_json(&json!({
            "cniVersion": requested,
            "supportedVersions": SUPPORTED_VERSIONS,
        })) {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
        return;
    }

    let input = match read_stdin() {
        Ok(input) => input,
        Err(error) => {
            print_error("1.0.0", &error);
            std::process::exit(1);
        }
    };
    let config: PluginConfig = match serde_json::from_slice(&input) {
        Ok(config) => config,
        Err(error) => {
            print_error("1.0.0", &error.into());
            std::process::exit(1);
        }
    };
    let result = match args.command.as_str() {
        "ADD" => add(&config, &input, &args).await.and_then(|result| {
            print_json(&result)?;
            Ok(())
        }),
        "DEL" => delete(&config, &input, &args).await,
        "CHECK" => check(&config, &input, &args).await,
        command => Err(anyhow::anyhow!("unsupported CNI_COMMAND {command:?}")),
    };
    if let Err(error) = result {
        print_error(&config.cni_version, &error);
        std::process::exit(1);
    }
}
