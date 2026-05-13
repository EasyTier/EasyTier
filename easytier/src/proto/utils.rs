use delegate::delegate;
use derivative::Derivative;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, IntoIterator};
use prost::Message;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Generates a stable digest strictly within the lifecycle of the current process.
///
/// ⚠️ WARNING:
/// - This digest is ONLY guaranteed to be deterministic within a **single process and the exact same binary build**.
pub trait TransientDigest: Message {
    fn digest(&self) -> [u8; 32]
    where
        Self: Sized,
    {
        let buf = self.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(buf);
        hasher.finalize().into()
    }
}

impl<S: Message> TransientDigest for S {}

pub trait MessageModel<Message: prost::Message>:
    Into<Message> + for<'m> TryFrom<&'m Message>
{
}

impl<Message, Model> MessageModel<Message> for Model
where
    Message: prost::Message,
    Model: Into<Message> + for<'m> TryFrom<&'m Message>,
{
}

#[derive(
    Derivative, Debug, Clone, PartialEq, Eq, Hash, From, Deref, DerefMut, AsRef, AsMut, IntoIterator,
)]
#[derivative(Default(bound = ""))]
#[as_ref(forward)]
#[as_mut(forward)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model> {
    pub models: Vec<Model>,
}

impl<Model> FromIterator<Model> for RepeatedMessageModel<Model> {
    fn from_iter<I: IntoIterator<Item = Model>>(iter: I) -> Self {
        Self {
            models: iter.into_iter().collect(),
        }
    }
}

impl<Model> Extend<Model> for RepeatedMessageModel<Model> {
    delegate! {
        to self.models {
            fn extend<T: IntoIterator<Item = Model>>(&mut self, iter: T);
        }
    }
}

impl<'m, Message, Model> TryFrom<&'m [Message]> for RepeatedMessageModel<Model>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    type Error = <Model as TryFrom<&'m Message>>::Error;

    fn try_from(value: &'m [Message]) -> Result<Self, Self::Error> {
        value.iter().map(TryInto::try_into).collect()
    }
}

impl<Message, Model> From<RepeatedMessageModel<Model>> for Vec<Message>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    fn from(value: RepeatedMessageModel<Model>) -> Self {
        value.into_iter().map(Into::into).collect()
    }
}

pub trait RepeatedSerialize: Serialize + Sized {
    fn serialize<S>(models: &RepeatedMessageModel<Self>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&**models, serializer)
    }
}

pub trait RepeatedDeserialize<'de>: Deserialize<'de> {
    fn deserialize<D>(deserializer: D) -> Result<RepeatedMessageModel<Self>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::deserialize(deserializer).map(Into::into)
    }

    #[doc(hidden)]
    fn deserialize_in_place<D>(
        deserializer: D,
        place: &mut RepeatedMessageModel<Self>,
    ) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize_in_place(deserializer, &mut place.models)
    }
}

impl<Model: RepeatedSerialize> Serialize for RepeatedMessageModel<Model> {
    delegate! {
        #[through(RepeatedSerialize)]
        to self {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer;
        }
    }
}

impl<'de, Model: RepeatedDeserialize<'de>> Deserialize<'de> for RepeatedMessageModel<Model> {
    delegate! {
        to RepeatedDeserialize {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>;

            #[doc(hidden)]
            fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
            where
                D: Deserializer<'de>;
        }
    }
}
