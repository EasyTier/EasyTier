use delegate::delegate;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, IntoIterator};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub trait CollectionExt: IntoIterator + Sized {
    fn convert<T, C>(self) -> C
    where
        Self::Item: Into<T>,
        C: FromIterator<T>,
    {
        self.into_iter().map(Into::into).collect()
    }

    fn try_convert<T, C, E>(self) -> Result<C, E>
    where
        Self::Item: TryInto<T, Error = E>,
        C: FromIterator<T>,
    {
        self.into_iter().map(TryInto::try_into).collect()
    }
}

impl<I: IntoIterator> CollectionExt for I {}

pub trait MessageModel<Message: prost::Message>:
    Into<Message> + TryFrom<Message> + for<'m> TryFrom<&'m Message>
{
}

impl<Message, Model> MessageModel<Message> for Model
where
    Message: prost::Message,
    Model: Into<Message> + TryFrom<Message> + for<'m> TryFrom<&'m Message>,
{
}

#[derive(
    Educe, Debug, Clone, PartialEq, Eq, Hash, From, Deref, DerefMut, AsRef, AsMut, IntoIterator,
)]
#[educe(Default)]
#[as_ref(forward)]
#[as_mut(forward)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model> {
    pub models: Vec<Model>,
}

impl<Model> FromIterator<Model> for RepeatedMessageModel<Model> {
    fn from_iter<I: IntoIterator<Item = Model>>(iter: I) -> Self {
        Self {
            models: iter.convert(),
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
        value.try_convert()
    }
}

impl<Message, Model> From<RepeatedMessageModel<Model>> for Vec<Message>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    fn from(value: RepeatedMessageModel<Model>) -> Self {
        value.convert()
    }
}

impl<Model> RepeatedMessageModel<Model> {
    pub fn try_from_iter<Message>(
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<Self, <Model as TryFrom<Message>>::Error>
    where
        Message: prost::Message,
        Model: MessageModel<Message>,
    {
        messages.try_convert()
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
