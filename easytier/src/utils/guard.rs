use crate::utils::task::DetachableTask;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

pub trait CallableGuard<const ASYNC: bool, C> {
    type Output;
    fn call(self, context: C) -> Self::Output;
}

impl<C, G> CallableGuard<false, C> for G
where
    G: FnOnce(C),
{
    type Output = ();

    fn call(self, context: C) -> Self::Output {
        self(context)
    }
}

impl<C, G, F> CallableGuard<true, C> for G
where
    G: FnOnce(C) -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    type Output = DetachableTask<F>;

    fn call(self, context: C) -> Self::Output {
        self(context).into()
    }
}

pub struct ContextGuard<const ASYNC: bool, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    __context: ManuallyDrop<C>,
    __guard: ManuallyDrop<G>,
}

impl<const ASYNC: bool, C, G> Deref for ContextGuard<ASYNC, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.__context
    }
}

impl<const ASYNC: bool, C, G> DerefMut for ContextGuard<ASYNC, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.__context
    }
}

impl<const ASYNC: bool, C, G> ContextGuard<ASYNC, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    pub fn new<R>(context: C, guard: G) -> Self
    where
        G: FnOnce(C) -> R,
    {
        ContextGuard {
            __context: ManuallyDrop::new(context),
            __guard: ManuallyDrop::new(guard),
        }
    }
}

impl<const ASYNC: bool, C, G> ContextGuard<ASYNC, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    unsafe fn call(&mut self) -> G::Output {
        unsafe {
            let context = ManuallyDrop::take(&mut self.__context);
            let guard = ManuallyDrop::take(&mut self.__guard);

            guard.call(context)
        }
    }

    pub fn trigger(self) -> G::Output {
        let mut this = ManuallyDrop::new(self);
        unsafe { this.call() }
    }

    pub fn defuse(self) -> C {
        let mut this = ManuallyDrop::new(self);
        unsafe {
            ManuallyDrop::drop(&mut this.__guard);
            ManuallyDrop::take(&mut this.__context)
        }
    }
}

impl<const ASYNC: bool, C, G> Drop for ContextGuard<ASYNC, C, G>
where
    G: CallableGuard<ASYNC, C>,
{
    fn drop(&mut self) {
        let _ = unsafe { self.call() };
    }
}
