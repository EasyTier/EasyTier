//! Generates the plain Rust FlagsPatch with optionize, separately from the
//! schema defaults and form keys written by flags.

use std::fmt::Write as _;

use anyhow::{Context as _, bail};
use prost_reflect::{DescriptorPool, Kind};

/// Let optionize generate the configuration patch, keeping protobuf JSON's
/// aliases, numeric strings and enum names at the Serde boundary. Protobuf's
/// field attributes belong only to the complete message; a nullable field in
/// the patch needs its own presence in addition to its nullable value.
pub fn configure(descriptor_set: &[u8], config: &mut prost_build::Config) -> anyhow::Result<()> {
    let pool = DescriptorPool::decode(descriptor_set)?;
    let message = pool
        .get_message_by_name("common.Flags")
        .context("the compiled schema declares no common.Flags")?;
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
        let nullable = field.supports_presence();
        let mut serde = "default, skip_serializing_if = \"Option::is_none\"".to_owned();
        if field.json_name() != field.name() {
            write!(serde, ", alias = {:?}", field.json_name())?;
        }
        let adapter = match field.kind() {
            Kind::Bool | Kind::String if !nullable => None,
            Kind::Bool | Kind::String => Some("_".to_owned()),
            Kind::Uint32 => {
                Some("serde_with::PickFirst<(_, serde_with::DisplayFromStr)>".to_owned())
            }
            Kind::Uint64 => {
                Some("serde_with::PickFirst<(serde_with::DisplayFromStr, _)>".to_owned())
            }
            Kind::Enum(enumeration) => {
                Some(format!("serde_with::TryFromInto<{}>", enumeration.name()))
            }
            kind => bail!(
                "common.Flags.{} has unsupported kind {kind:?}",
                field.name()
            ),
        };
        let mut attrs = format!("serde({serde})");
        if let Some(adapter) = adapter {
            let adapter = if nullable {
                format!("flags::Presence<{adapter}>")
            } else {
                format!("Option<{adapter}>")
            };
            write!(attrs, ", serde_as(as = {adapter:?})")?;
        }
        config.field_attribute(
            format!(".common.Flags.{}", field.name()),
            format!("#[optionize(attrs(.., -prost, {attrs}))]"),
        );
    }
    Ok(())
}
