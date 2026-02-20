use derive_more::{Deref, DerefMut, From, IntoIterator};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use crate::dns::utils::MapTryInto;

pub trait MessageModel<Message: prost::Message>: Into<Message> + for<'m> TryFrom<&'m Message> {}

impl<Message, Model> MessageModel<Message> for Model
where
    Message: prost::Message,
    Model: Into<Message> + for<'m> TryFrom<&'m Message>,
{
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, From, Deref, DerefMut, Serialize, Deserialize, IntoIterator,
)]
#[serde(transparent)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model>(Vec<Model>);

impl<Model> Default for RepeatedMessageModel<Model>
{
    fn default() -> Self {
        Self(vec![])
    }
}

impl<'m, Message, Model> TryFrom<&'m Vec<Message>> for RepeatedMessageModel<Model>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    type Error = <Model as TryFrom<&'m Message>>::Error;

    fn try_from(value: &'m Vec<Message>) -> Result<Self, Self::Error> {
        Ok(Self(value.map_try_into().collect::<Result<Vec<_>, _>>()?))
    }
}

impl<Message, Model> From<RepeatedMessageModel<Model>> for Vec<Message>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    fn from(value: RepeatedMessageModel<Model>) -> Self {
        value.into_iter().map_into().collect()
    }
}
