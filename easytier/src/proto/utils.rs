use crate::utils::MapTryInto;
use derivative::Derivative;
use derive_more::{Deref, DerefMut, From, IntoIterator};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

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
        Ok(Self(value.into_iter().map_try_into().try_collect()?))
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
