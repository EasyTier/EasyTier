use prost::Message;
use sha2::{Digest, Sha256};
use derivative::Derivative;
use derive_more::{Deref, DerefMut, From, IntoIterator};
use serde::{Deserialize, Serialize};

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

impl<'m, Message, Model> TryFrom<&'m Vec<Message>> for RepeatedMessageModel<Model>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    type Error = <Model as TryFrom<&'m Message>>::Error;

    fn try_from(value: &'m Vec<Message>) -> Result<Self, Self::Error> {
        Ok(Self(
            value
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        ))
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
