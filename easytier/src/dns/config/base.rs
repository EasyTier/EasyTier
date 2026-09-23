use derivative::Derivative;
use derive_more::{Constructor, Deref};
use getset::Getters;
use optionize::Optionized;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(Derivative, Debug, Clone, Constructor, Getters, Deref, Deserialize)]
#[derivative(PartialEq(bound = "Parsed: PartialEq"))]
#[serde(try_from = "Raw")]
#[serde(
    bound = "Raw: Deserialize<'de>, <ConfigBase<Raw, Parsed, Data> as TryFrom<Raw>>::Error: Display"
)]
pub struct ConfigBase<Raw, Parsed, Data = ()>
where
    Raw: Optionized<Subject = Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
{
    #[deref]
    parsed: Parsed,
    #[getset(get = "pub")]
    #[derivative(PartialEq = "ignore")]
    raw: Raw,
    #[getset(get = "pub")]
    #[derivative(PartialEq = "ignore")]
    data: Data,
}

impl<Raw, Parsed, Data> Serialize for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Subject = Parsed> + Serialize,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw, Error: Debug>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

impl<Raw, Parsed, Data> Default for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Subject = Parsed> + Default,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw, Error: Debug>,
{
    fn default() -> Self {
        Raw::default().try_into().unwrap()
    }
}

impl<Raw, Parsed, Data> ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Subject = Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw, Error: Debug>,
{
    pub fn into_parsed(self) -> Parsed {
        self.parsed
    }
    #[cfg(test)]
    pub fn into_raw(self) -> Raw {
        self.raw
    }
    pub fn into_data(self) -> Data {
        self.data
    }
}
