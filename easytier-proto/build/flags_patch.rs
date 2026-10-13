//! Generates the plain Rust FlagsPatch with optionize, separately from the
//! schema defaults and form keys written by flags.

use std::fmt::Write as _;

use anyhow::{Context as _, bail};
use prost_reflect::{DescriptorPool, Value};

/// Generate the configuration patch with common Serde defaults and JSON-name
/// aliases. Field-specific optionize and Serde rules live in the schema.
pub fn configure(descriptor_set: &[u8], config: &mut prost_build::Config) -> anyhow::Result<()> {
    let pool = DescriptorPool::decode(descriptor_set)?;
    let message = pool
        .get_message_by_name("common.Flags")
        .context("the compiled schema declares no common.Flags")?;
    let extension = pool
        .get_extension_by_name("easytier.flag")
        .context("annotations.proto declares no easytier.flag")?;
    let names = crate::flags::field_names(&message, &extension)?;
    config
        .type_attribute(".common.Flags", "#[optionize::optionized]")
        .type_attribute(
            ".common.Flags",
            "#[optionize(name = \"{}Patch\", attrs(\
                serde_with::serde_as, \
                derive(Clone, Debug, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize), \
                serde(deny_unknown_fields)))]",
        );

    for field in message.fields() {
        let Value::Message(meta) = field.options().get_extension(&extension).into_owned() else {
            bail!("easytier.flag on {} is not a message", field.name());
        };
        let mut serde = "default, skip_serializing_if = \"Option::is_none\"".to_owned();
        if let Some(names) = names.get(field.name()) {
            for alias in names.iter().filter(|name| *name != field.name()) {
                write!(serde, ", alias = {alias:?}")?;
            }
        }
        let path = format!(".common.Flags.{}", field.name());
        config.field_attribute(
            &path,
            format!("#[optionize(attrs(.., -prost, serde({serde})))]"),
        );

        if let Some(Value::List(options)) = meta.get_field_by_name("optionize").as_deref() {
            for option in options {
                let Value::String(option) = option else {
                    bail!("common.Flags.{}: optionize is not text", field.name());
                };
                config.field_attribute(&path, format!("#[optionize({option})]"));
            }
        }
    }
    Ok(())
}
