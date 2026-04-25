use crate::utils::task::{DetachableTask, TaskSpawner};
use std::fmt::Debug;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

pub trait CallableGuard<const ASYNC: bool, Context> {
    type Output;
    fn call(self, context: Context) -> Self::Output;
}

impl<Context, Guard> CallableGuard<false, Context> for Guard
where
    Guard: FnOnce(Context),
{
    type Output = ();

    fn call(self, context: Context) -> Self::Output {
        self(context)
    }
}

impl<Context, Guard, Task> CallableGuard<true, Context> for Guard
where
    Guard: FnOnce(Context) -> Task + Send + 'static,
    Task: Future<Output = ()> + Send + 'static,
{
    type Output = DetachableTask<TaskSpawner<Task>, Task>;

    fn call(self, context: Context) -> Self::Output {
        DetachableTask::new(self(context))
    }
}

pub struct ContextGuard<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>> {
    context: ManuallyDrop<Context>,
    guard: ManuallyDrop<Guard>,
}

impl<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>> Deref
    for ContextGuard<ASYNC, Context, Guard>
{
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>> DerefMut
    for ContextGuard<ASYNC, Context, Guard>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.context
    }
}

impl<const ASYNC: bool, Context: Debug, Guard: CallableGuard<ASYNC, Context>> Debug
    for ContextGuard<ASYNC, Context, Guard>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = if ASYNC {
            "ContextGuard::Async"
        } else {
            "ContextGuard::Sync"
        };
        f.debug_struct(name)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>>
    ContextGuard<ASYNC, Context, Guard>
{
    pub fn new<_R>(context: Context, guard: Guard) -> Self
    where
        Guard: FnOnce(Context) -> _R,
    {
        ContextGuard {
            context: ManuallyDrop::new(context),
            guard: ManuallyDrop::new(guard),
        }
    }
}

impl<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>>
    ContextGuard<ASYNC, Context, Guard>
{
    unsafe fn call(&mut self) -> Guard::Output {
        unsafe {
            let context = ManuallyDrop::take(&mut self.context);
            let guard = ManuallyDrop::take(&mut self.guard);

            guard.call(context)
        }
    }

    pub fn trigger(self) -> Guard::Output {
        let mut this = ManuallyDrop::new(self);
        unsafe { this.call() }
    }

    pub fn defuse(self) -> Context {
        let mut this = ManuallyDrop::new(self);
        unsafe {
            ManuallyDrop::drop(&mut this.guard);
            ManuallyDrop::take(&mut this.context)
        }
    }
}

impl<const ASYNC: bool, Context, Guard: CallableGuard<ASYNC, Context>> Drop
    for ContextGuard<ASYNC, Context, Guard>
{
    fn drop(&mut self) {
        let _: Guard::Output = unsafe { self.call() };
    }
}

// region macro

#[doc(hidden)]
#[macro_export]
macro_rules! __guarded {
    (@parse@action $guard:ident => $($tt:tt)*) => {
        $crate::__guarded! { @parse@async action: [ @stmt $guard ] ; $($tt)* }
    };

    (@parse@action $($tt:tt)*) => {
        $crate::__guarded! { @parse@async action: [ @stmt __guard ] ; $($tt)* }
    };

    (@parse@async action: [ $($action:tt)* ] ; sync $($tt:tt)*) => {
        $crate::__guarded! { @parse@move action: [ $($action)* ] ; async: [ false ] ; $($tt)* }
    };

    (@parse@async action: [ $($action:tt)* ] ; $($tt:tt)*) => {
        $crate::__guarded! { @parse@move action: [ $($action)* ] ; async: [ _ ] ; $($tt)* }
    };

    (@parse@move action: [ $($action:tt)* ] ; async: [ $async:tt ] ; move $($tt:tt)*) => {
        $crate::__guarded! { @parse action: [ $($action)* ] ; async: [ $async ] ; move: [ move ] ; $($tt)* }
    };

    (@parse@move action: [ $($action:tt)* ] ; async: [ $async:tt ] ; $($tt:tt)*) => {
        $crate::__guarded! { @parse action: [ $($action)* ] ; async: [ $async ] ; move: [] ; $($tt)* }
    };

    (
        @parse action: [ $($action:tt)* ] ; async: [ $async:tt ] ; move: [ $($move:tt)? ] ;
        [ $($args:tt)* ] $body:block
    ) => {
        $crate::__guarded! {
            action: [ $($action)* ]
            async: [ $async ]
            move: [ $($move)? ]
            mut: []
            rest: [ $($args)* , ]
            args: []
            vars: []
            body: [ $body ]
        }
    };

    (
        @parse action: [ $($action:tt)* ] ; async: [ $async:tt ] ; move: [ $($move:tt)? ] ;
        $body:block
    ) => {
        $crate::__guarded! {
            @parse action: [ $($action)* ] ; async: [ $async ] ; move: [ $($move)? ] ;
            [] $body
        }
    };

    (
        @parse action: [ $($action:tt)* ] ; async: [ $async:tt ] ; move: [ $($move:tt)? ] ;
        [ $($args:tt)* ] $($body:tt)*
    ) => {
        $crate::__guarded! {
            @parse action: [ $($action)* ] ; async: [ $async ] ; move: [ $($move)? ] ;
            [ $($args)* ] { $($body)* }
        }
    };

    (
        @parse action: [ $($action:tt)* ] ; async: [ $async:tt ] ; move: [ $($move:tt)? ] ;
        $($body:tt)*
    ) => {
        $crate::__guarded! {
            @parse action: [ $($action)* ] ; async: [ $async ] ; move: [ $($move)? ] ;
            [] { $($body)* }
        }
    };

    (
        action: [ $($action:tt)* ]
        async: [ $async:tt ]
        move: [ $($move:tt)? ]
        mut: [ $($mut:tt)? ]
        rest: [ mut $arg:ident , $($rest:tt)* ]
        args: [ $($args:ident)* ]
        vars: [ $($vars:tt)* ]
        body: [ $body:expr ]
    ) => {
        $crate::__guarded! {
            action: [ $($action)* ]
            async: [ $async ]
            move: [ $($move)? ]
            mut: [ mut ]
            rest: [ $($rest)* ]
            args: [ $($args)* $arg ]
            vars: [ $($vars)* [mut $arg] ]
            body: [ $body ]
        }
    };

    (
        action: [ $($action:tt)* ]
        async: [ $async:tt ]
        move: [ $($move:tt)? ]
        mut: [ $($mut:tt)? ]
        rest: [ $arg:ident , $($rest:tt)* ]
        args: [ $($args:ident)* ]
        vars: [ $($vars:tt)* ]
        body: [ $body:expr ]
    ) => {
        $crate::__guarded! {
            action: [ $($action)* ]
            async: [ $async ]
            move: [ $($move)? ]
            mut: [ $($mut)? ]
            rest: [ $($rest)* ]
            args: [ $($args)* $arg ]
            vars: [ $($vars)* [$arg] ]
            body: [ $body ]
        }
    };

    (
        action: [ @stmt $guard:ident ]
        async: [ $async:tt ]
        move: [ $($move:tt)? ]
        mut: [ $($mut:tt)? ]
        rest: [ $(,)* ]
        args: [ $($args:ident)* ]
        vars: [ $([$($vars:tt)*])* ]
        body: [ $body:expr ]
    ) => {
        let $($mut)? $guard = $crate::utils::guard::ContextGuard::<$async, _, _>::new(
            ( $($args),* ),
            $($move)? |#[allow(unused_parens, unused_mut)] ( $($($vars)*),* )| $body
        );

        #[allow(unused_parens, unused_variables, clippy::toplevel_ref_arg)]
        let ( $(ref $($vars)*),* ) = *$guard;
    };

    (
        action: [ @expr ]
        async: [ $async:tt ]
        move: [ $($move:tt)? ]
        mut: [ $($mut:tt)? ]
        rest: [ $(,)* ]
        args: [ $($args:ident)* ]
        vars: [ $([$($vars:tt)*])* ]
        body: [ $body:expr ]
    ) => {
        $crate::utils::guard::ContextGuard::<$async, _, _>::new(
            ( $($args),* ),
            $($move)? |#[allow(unused_parens)] ( $($($vars)*),* )| $body
        )
    };
}

#[macro_export]
macro_rules! guarded {
    ( $($tt:tt)* ) => {
        $crate::__guarded! { @parse@action $($tt)* }
    };
}

#[macro_export]
macro_rules! guard {
    ( $($tt:tt)* ) => {
        $crate::__guarded! { @parse@async action: [ @expr ] ; $($tt)* }
    };
}

// endregion

#[macro_export]
macro_rules! defer {
    ( $($tt:tt)* ) => {
        $crate::guarded! { $($tt)* }
    };
}
