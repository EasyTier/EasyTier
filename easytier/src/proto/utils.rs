use delegate::delegate;
use derivative::Derivative;
use derive_more::{Deref, DerefMut, From, IntoIterator};
use prost::Message;
use serde::{Deserialize, Serialize};
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
    Derivative,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    From,
    Deref,
    DerefMut,
    Serialize,
    Deserialize,
    IntoIterator,
)]
#[derivative(Default(bound = ""))]
#[serde(transparent)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model>(Vec<Model>);

impl<Model> RepeatedMessageModel<Model> {
    pub fn into_inner(self) -> Vec<Model> {
        self.0
    }
}

impl<Model> FromIterator<Model> for RepeatedMessageModel<Model> {
    fn from_iter<I: IntoIterator<Item = Model>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<Model> Extend<Model> for RepeatedMessageModel<Model> {
    delegate! {
        to self.0 {
            fn extend<T: IntoIterator<Item = Model>>(&mut self, iter: T);
        }
    }
}

impl<Model> AsRef<[Model]> for RepeatedMessageModel<Model> {
    delegate! {
        to self.0 {
            fn as_ref(&self) -> &[Model];
        }
    }
}

impl<Model> AsMut<[Model]> for RepeatedMessageModel<Model> {
    delegate! {
        to self.0 {
            fn as_mut(&mut self) -> &mut [Model];
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
