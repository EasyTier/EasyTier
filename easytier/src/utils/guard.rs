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

#[doc(hidden)]
#[macro_export]
macro_rules! __guarded {
    (
        [ mut $arg:ident , $($rest:tt)* ]
        mut: [ $($mut:tt)? ]
        guard: [ $guard:ident ]
        args: [ $($args:ident),* ]
        vars: [ $([$($vars:tt)*])* ]
        body: [ $body:expr ]
    ) => {
        $crate::__guarded! {
            [ $($rest)* ]
            mut: [ mut ]
            guard: [ $guard ]
            args: [ $($args,)* $arg ]
            vars: [ $([$($vars)*])* [mut $arg] ]
            body: [ $body ]
        }
    };

    (
        [ $arg:ident , $($rest:tt)* ]
        mut: [ $($mut:tt)? ]
        guard: [ $guard:ident ]
        args: [ $($args:ident),* ]
        vars: [ $([$($vars:tt)*])* ]
        body: [ $body:expr ]
    ) => {
        $crate::__guarded! {
            [ $($rest)* ]
            mut: [ $($mut)? ]
            guard: [ $guard ]
            args: [ $($args,)* $arg ]
            vars: [ $([$($vars)*])* [$arg] ]
            body: [ $body ]
        }
    };

    (
        [ $(,)* ]
        mut: [ $($mut:tt)? ]
        guard: [ $guard:ident ]
        args: [ $($args:ident),* ]
        vars: [ $([$($vars:tt)*])* ]
        body: [ $body:expr ]
    ) => {
        let $($mut)? $guard = $crate::utils::guard::ContextGuard::new(
            ( $($args),* ),
            |#[allow(unused_parens, unused_mut)] ( $($($vars)*),* )| $body
        );

        #[allow(unused_parens, unused_variables, clippy::toplevel_ref_arg)]
        let ( $(ref $($vars)*),* ) = *$guard;
    };
}

#[macro_export]
macro_rules! guarded {
    ( $guard:ident = [ $($args:tt)* ] $body:block ) => {
        $crate::__guarded! {
            [ $($args)* , ]
            mut: []
            guard: [ $guard ]
            args: []
            vars: []
            body: [ $body ]
        }
    };

    ( [ $($args:tt)* ] $body:block ) => {
        $crate::guarded! {
            __guard = [ $($args)* ] $body
        }
    };

    ( $guard:ident = [ $($args:tt)* ] $($body:tt)* ) => {
        $crate::guarded! { $guard = [ $($args)* ] { $($body)*; } }
    };

    ( [ $($args:tt)* ] $($body:tt)* ) => {
        $crate::guarded! { [ $($args)* ] { $($body)*; } }
    };
}

#[macro_export]
macro_rules! guard {
    ( [ $($args:tt)* ] $($body:tt)* ) => {{
        $crate::guarded! { __guard = [ $($args)* ] $($body)* }
        __guard
    }};
    ( $($body:tt)* ) => {{
        $crate::guarded! { __guard = [] { $($body)* } }
        __guard
    }};
}

#[macro_export]
macro_rules! defer {
    ( $($body:tt)* ) => {
        $crate::guarded! { [] { $($body)* } }
    };
}
