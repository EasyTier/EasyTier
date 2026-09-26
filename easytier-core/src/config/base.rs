use std::fmt::{Debug, Display};

use optionize::Optionized;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(try_from = "Raw")]
#[serde(
    bound = "Raw: Deserialize<'de>, <ConfigBase<Raw, Parsed, Data> as TryFrom<Raw>>::Error: Display"
)]
pub struct ConfigBase<Raw, Parsed, Data = ()>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
{
    parsed: Parsed,
    raw: Raw,
    data: Data,
}

impl<Raw, Parsed, Data> std::ops::Deref for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
{
    type Target = Parsed;

    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}

impl<Raw, Parsed, Data> PartialEq for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
    Parsed: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.parsed == other.parsed
    }
}

impl<Raw, Parsed, Data> Eq for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
    Parsed: Eq,
{
}

impl<Raw: Clone, Parsed: Clone, Data: Clone> Clone for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
{
    fn clone(&self) -> Self {
        Self {
            parsed: self.parsed.clone(),
            raw: self.raw.clone(),
            data: self.data.clone(),
        }
    }
}

impl<Raw: Debug, Parsed: Debug, Data: Debug> Debug for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigBase")
            .field("parsed", &self.parsed)
            .field("raw", &self.raw)
            .field("data", &self.data)
            .finish()
    }
}

impl<Raw, Parsed, Data> Serialize for ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed> + Serialize,
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
    Raw: Optionized<Parsed> + Default,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw, Error: Debug>,
{
    fn default() -> Self {
        Raw::default().try_into().unwrap()
    }
}

impl<Raw, Parsed, Data> ConfigBase<Raw, Parsed, Data>
where
    Raw: Optionized<Parsed>,
    ConfigBase<Raw, Parsed, Data>: TryFrom<Raw, Error: Debug>,
{
    pub fn new(parsed: Parsed, raw: Raw, data: Data) -> Self {
        Self { parsed, raw, data }
    }

    pub fn parsed(&self) -> &Parsed {
        &self.parsed
    }

    pub fn raw(&self) -> &Raw {
        &self.raw
    }

    pub fn data(&self) -> &Data {
        &self.data
    }

    pub fn into_parsed(self) -> Parsed {
        self.parsed
    }

    pub fn into_raw(self) -> Raw {
        self.raw
    }

    pub fn into_data(self) -> Data {
        self.data
    }

    pub fn is_empty(&self) -> bool
    where
        Raw: Default + PartialEq,
    {
        self.raw == Raw::default()
    }
}
