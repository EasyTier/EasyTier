use delegate::delegate;
use derivative::Derivative;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into, IntoIterator};
use std::fmt;
use std::fmt::Display;
use thiserror::Error;

#[derive(Derivative, Debug, From, Into, Deref, DerefMut, AsRef, AsMut, IntoIterator, Error)]
#[derivative(Default(bound = ""))]
#[as_ref(forward)]
#[as_mut(forward)]
#[into_iterator(owned, ref, ref_mut)]
pub struct ErrorCollection<E> {
    pub errors: Vec<E>,
}

impl<E> ErrorCollection<E> {
    delegate! {
        to Vec {
            #[into]
            pub fn new() -> Self;
            #[into]
            pub fn with_capacity(capacity: usize) -> Self;
        }
    }
}

impl<E, Item: Into<E>> FromIterator<Item> for ErrorCollection<E> {
    fn from_iter<I: IntoIterator<Item = Item>>(iter: I) -> Self {
        Self {
            errors: iter.into_iter().map(Into::into).collect(),
        }
    }
}

impl<E> Extend<E> for ErrorCollection<E> {
    delegate! {
        to self.errors {
            fn extend<T: IntoIterator<Item = E>>(&mut self, iter: T);
        }
    }
}

impl<E: Display> Display for ErrorCollection<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "No errors");
        }

        write!(f, "{} error(s) occurred:", self.errors.len())?;
        for (i, err) in self.errors.iter().enumerate() {
            writeln!(f)?;
            write!(f, "  {}. {}", i + 1, err)?;
        }

        Ok(())
    }
}
