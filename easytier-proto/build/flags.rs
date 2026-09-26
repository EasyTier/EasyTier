//! Reads the `(easytier.flag)` annotations off `common.Flags` and writes them
//! out as Rust the crate compiles in.
//!
//! Each annotation carries what the core runs for a flag a configuration does
//! not state, the name the management API spells it with, and whether a config
//! form offers it. Nothing here is a second list: the field, its type and its
//! presence are the schema's, and an unannotated field fails the build.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail, ensure};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, Value};

const EXPLICIT_FIELDS: &[&str] = &["mtu", "relay_network_whitelist", "data_compress_algo"];

const CORE_ONLY_FLAGS: &[&str] = &[
    "default_protocol",
    "foreign_relay_bps_limit",
    "multi_thread_count",
    "enable_relay_foreign_network_kcp",
    "enable_relay_foreign_network_quic",
    "disable_relay_kcp",
    "disable_relay_quic",
    "tld_dns_zone",
];

pub fn write(descriptor_set: &[u8], out: &Path) -> anyhow::Result<PathBuf> {
    let pool = DescriptorPool::decode(descriptor_set)?;
    let message = pool
        .get_message_by_name("common.Flags")
        .context("the compiled schema declares no common.Flags")?;
    let extension = pool
        .get_extension_by_name("easytier.flag")
        .context("annotations.proto declares no easytier.flag")?;
    // A form reads and writes the management API, so a flag it manages has to
    // be one the API carries.
    let api = pool
        .get_message_by_name("api.manage.NetworkConfig")
        .context("the compiled schema declares no api.manage.NetworkConfig")?;
    let api_carries = |name: &str| api.get_field_by_name(name).is_some();

    let mut defaults: Vec<String> = Vec::new();
    let mut form = String::new();
    let mut to_net = String::new();
    let mut to_flags = String::new();

    for field in message.fields() {
        let name = field.name();
        let options = field.options();
        ensure!(
            options.has_extension(&extension),
            "common.Flags.{name} carries no (easytier.flag) annotation"
        );
        let Value::Message(meta) = options.get_extension(&extension).into_owned() else {
            bail!("easytier.flag on common.Flags.{name} is not a message");
        };

        // The value the flag runs with, written the way its type reads; JSON
        // needs quotes around text, and an optional flag that states nothing
        // is the one that runs unset. What the value *means* is protobuf's to
        // say when the crate reads this document back.
        let value = match text(&meta, "default", name)? {
            Some(text) => match field.kind() {
                Kind::String | Kind::Enum(_) => serde_json::to_string(&text)?,
                _ => text,
            },
            None if field.supports_presence() => "null".to_owned(),
            None => bail!("common.Flags.{name} states no default"),
        };
        defaults.push(format!("    {name:?}: {value}"));

        // The name the management API uses, where the flag's own name is not it.
        let spelling = match meta.get_field_by_name("api").as_deref() {
            Some(Value::Message(api)) => match api.get_field_by_name("field").as_deref() {
                Some(Value::String(field)) if !field.is_empty() => Some(field.clone()),
                _ => None,
            },
            Some(_) => bail!("common.Flags.{name}: the api spelling is not a message"),
            _ => None,
        };
        if let Some(spelling) = &spelling {
            ensure!(
                api_carries(spelling),
                "common.Flags.{name} is spelled {spelling} by the management API, \
                 which carries no such field"
            );
        }

        let negate = match meta.get_field_by_name("api").as_deref() {
            Some(Value::Message(api)) => match api.get_field_by_name("negate").as_deref() {
                Some(Value::Bool(negate)) => *negate,
                _ => false,
            },
            _ => false,
        };

        let deprecated = is_set(&meta, "deprecated");

        ensure!(
            deprecated
                == matches!(
                    options.get_field_by_name("deprecated").as_deref(),
                    Some(Value::Bool(true))
                ),
            "common.Flags.{name}: the annotation says deprecated = {deprecated}, \
             but the field says the contrary"
        );

        // The keys a config form owns, named as the management API names them.
        //
        // Only what the API carries can be a key here: the merge drops a key
        // the form produces nothing for, so a flag the API cannot express
        // would be deleted from a stored configuration on every save.
        let api_name = spelling.as_deref().unwrap_or(name);
        if is_set(&meta, "form") {
            ensure!(
                api_carries(api_name),
                "common.Flags.{name} says a form has a control for it, but \
                 api.manage.NetworkConfig carries no {api_name}"
            );
        }
        if !deprecated
            && api_carries(api_name)
            && (matches!(field.kind(), Kind::Bool) || is_set(&meta, "form"))
        {
            writeln!(form, "    {api_name:?},")?;
        }

        if deprecated {
            continue;
        }

        if EXPLICIT_FIELDS.contains(&name) {
            ensure!(
                api_carries(api_name),
                "explicit field common.Flags.{name} is not carried by api.manage.NetworkConfig"
            );
            continue;
        }

        if !api_carries(api_name) {
            ensure!(
                CORE_ONLY_FLAGS.contains(&name),
                "common.Flags.{name} is not carried by api.manage.NetworkConfig and not in CORE_ONLY_FLAGS; add mapping or declare core-only"
            );
            continue;
        }

        let api_field = api
            .get_field_by_name(api_name)
            .with_context(|| format!("NetworkConfig has no field {api_name}"))?;
        ensure!(
            api_field.supports_presence(),
            "NetworkConfig.{api_name} must support presence"
        );

        if negate {
            ensure!(
                matches!(field.kind(), Kind::Bool),
                "Flags.{name} is negated but is not bool"
            );
            ensure!(
                matches!(api_field.kind(), Kind::Bool),
                "NetworkConfig.{api_name} is negated but is not bool"
            );
            writeln!(to_net, "    result.{api_name} = flags.{name}.map(|v| !v);")?;
            writeln!(to_flags, "    flags.{name} = net.{api_name}.map(|v| !v);")?;
        } else {
            ensure!(
                field.kind() == api_field.kind(),
                "Flags.{name} ({:?}) and NetworkConfig.{api_name} ({:?}) type mismatch",
                field.kind(),
                api_field.kind()
            );
            if matches!(field.kind(), Kind::String) {
                writeln!(to_net, "    result.{api_name} = flags.{name}.clone();")?;
                writeln!(to_flags, "    flags.{name} = net.{api_name}.clone();")?;
            } else {
                writeln!(to_net, "    result.{api_name} = flags.{name};")?;
                writeln!(to_flags, "    flags.{name} = net.{api_name};")?;
            }
        }
    }

    let defaults = defaults.join(",\n");
    let generated = format!(
        "\
// @generated by easytier-proto's build script from the (easytier.flag)
// annotations on proto/common.proto. Do not edit.

/// The values a network runs with when a configuration states no flag, as the
/// schema declares them in protobuf JSON.
pub const DEFAULTS: &str = r##\"{{
{defaults}}}\"##;

/// The flags a config form manages, named as the management API names them.
pub const FORM: &[&str] = &[
{form}];

#[cfg(feature = \"api\")]
/// Copies mechanical flag values from `FlagsPatch` to `NetworkConfig`.
pub fn copy_flags_to_network_config(
    flags: &crate::common::FlagsPatch,
    result: &mut crate::api::manage::NetworkConfig,
) {{
{to_net}}}

#[cfg(feature = \"api\")]
/// Copies mechanical flag values from `NetworkConfig` to `FlagsPatch`.
pub fn copy_network_config_to_flags(
    net: &crate::api::manage::NetworkConfig,
    flags: &mut crate::common::FlagsPatch,
) {{
{to_flags}}}
"
    );

    let path = out.join("flags.rs");
    std::fs::write(&path, generated)?;
    Ok(path)
}

/// A text field of the annotation, absent when the annotation leaves it out.
fn text(meta: &DynamicMessage, field: &str, flag: &str) -> anyhow::Result<Option<String>> {
    if !meta.has_field_by_name(field) {
        return Ok(None);
    }
    match meta.get_field_by_name(field).as_deref() {
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => bail!("common.Flags.{flag}: {field} is {other:?}, expected text"),
        None => Ok(None),
    }
}

fn is_set(meta: &DynamicMessage, field: &str) -> bool {
    matches!(
        meta.get_field_by_name(field).as_deref(),
        Some(Value::Bool(true))
    )
}
