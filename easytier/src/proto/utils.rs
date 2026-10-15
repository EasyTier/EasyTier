use derive_more::{AsMut, AsRef, Deref, DerefMut, From, IntoIterator};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, From, Deref, DerefMut, AsRef, AsMut, IntoIterator)]
#[as_ref(forward)]
#[as_mut(forward)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model> {
    pub models: Vec<Model>,
}

impl<Model> Default for RepeatedMessageModel<Model> {
    fn default() -> Self {
        Self { models: Vec::new() }
    }
}

impl<Model> FromIterator<Model> for RepeatedMessageModel<Model> {
    fn from_iter<I: IntoIterator<Item = Model>>(iter: I) -> Self {
        Self {
            models: iter.into_iter().collect(),
        }
    }
}

impl<Model> Extend<Model> for RepeatedMessageModel<Model> {
    fn extend<T: IntoIterator<Item = Model>>(&mut self, iter: T) {
        self.models.extend(iter);
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
