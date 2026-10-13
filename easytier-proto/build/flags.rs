//! Reads the `(easytier.flag)` annotations off `common.Flags` and writes them
//! out as Rust the crate compiles in.
//!
//! Each annotation carries what the core runs for a flag a configuration does
//! not state, the name the management API spells it with, and whether a config
//! form offers it. Nothing here is a second list: the field, its type and its
//! presence are the schema's, and an unannotated field fails the build.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail, ensure};
use heck::ToLowerCamelCase as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, ExtensionDescriptor, Kind, MessageDescriptor, Value,
};

pub fn write(descriptor_set: &[u8], out: &Path) -> anyhow::Result<PathBuf> {
    let pool = DescriptorPool::decode(descriptor_set)?;
    let message = pool
        .get_message_by_name("common.Flags")
        .context("the compiled schema declares no common.Flags")?;
    let extension = pool
        .get_extension_by_name("easytier.flag")
        .context("annotations.proto declares no easytier.flag")?;
    let names = field_names(&message, &extension)?;
    // A form reads and writes the management API, so a flag it manages has to
    // be one the API carries.
    let api = pool
        .get_message_by_name("api.manage.NetworkConfig")
        .context("the compiled schema declares no api.manage.NetworkConfig")?;
    let api_carries = |name: &str| api.get_field_by_name(name).is_some();

    let mut defaults: Vec<String> = Vec::new();
    let mut form = String::new();
    let mut aliases = String::new();

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

        let deprecated = is_set(&meta, "deprecated");

        if !deprecated {
            for alias in names[name].iter().filter(|alias| *alias != name) {
                writeln!(aliases, "    ({alias:?}, {name:?}),")?;
            }
        }

        ensure!(
            deprecated
                == matches!(
                    options.get_field_by_name("deprecated").as_deref(),
                    Some(Value::Bool(true))
                ),
            "common.Flags.{name}: the annotation says deprecated = {deprecated}, \
             but the field says the contrary"
        );

        // The schema field names a config form owns, used as TOML keys.
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
            writeln!(form, "    {name:?},")?;
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

/// The schema field names of flags managed by the config form.
pub const FORM: &[&str] = &[
{form}];

/// Alternate input names paired with their canonical schema field names.
pub const ALIASES: &[(&str, &str)] = &[
{aliases}];
"
    );

    let path = out.join("flags.rs");
    std::fs::write(&path, generated)?;
    Ok(path)
}

/// Collect each field's name, JSON name and declared aliases, including the
/// camelCase spelling of every name. Aliases need not be protobuf fields.
pub(super) fn field_names(
    message: &MessageDescriptor,
    extension: &ExtensionDescriptor,
) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    let mut names = BTreeMap::<String, Vec<String>>::new();
    let mut owners = BTreeMap::<String, String>::new();
    for field in message.fields() {
        let name = field.name();
        let Value::Message(meta) = field.options().get_extension(extension).into_owned() else {
            bail!("easytier.flag on common.Flags.{name} is not a message");
        };
        let mut declared = vec![name.to_owned(), field.json_name().to_owned()];
        if let Some(Value::List(aliases)) = meta.get_field_by_name("alias").as_deref() {
            for alias in aliases {
                let Value::String(alias) = alias else {
                    bail!("common.Flags.{name}: alias is not text");
                };
                ensure!(!alias.is_empty(), "common.Flags.{name}: alias is empty");
                declared.push(alias.clone());
            }
        }
        let spellings = names.entry(name.to_owned()).or_default();
        for spelling in declared
            .iter()
            .flat_map(|name| [name.clone(), name.to_lower_camel_case()])
        {
            // Deprecated fields can retain their wire slot while a live
            // field accepts their old name. The old field explicitly skips
            // configuration input in its optionize annotation.
            if !is_set(&meta, "deprecated")
                && let Some(owner) = owners.insert(spelling.clone(), name.to_owned())
            {
                ensure!(
                    owner == name,
                    "flag name {spelling} refers to both {owner} and {name}"
                );
            }
            if !spellings.contains(&spelling) {
                spellings.push(spelling);
            }
        }
    }
    Ok(names)
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
