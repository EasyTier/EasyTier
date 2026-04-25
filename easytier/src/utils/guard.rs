//! # Guard Module Utilities
//!
//! This module provides mechanisms for scope-based resource management and deferred execution.
//!
//! ### ⚠️ Critical Usage Note: Diverging Expressions
//!
//! Do not use "naked" diverging expressions—such as `panic!`, `todo!`, or `loop {}`—as
//! the sole content of sync guard closure. This prevents the compiler from
//! distinguishing between synchronous (`ASYNC = false`) and asynchronous
//! (`ASYNC = true`) implementations, leading to a type inference error (E0277).
//!
//! ### Technical Context
//!
//! The `!` (Never Type) is a bottom type that can be coerced into any other type.
//! Because it satisfies both the `()` requirement for sync guards and the `Future`
//! requirement for async guards, the compiler encounters an inference deadlock.
//!
//! ### Workaround
//!
//! For macros like `guard!` or `guarded!`, force the closure to resolve to `()`
//! by explicitly setting the guard to `sync`:
//!
//! ```rust
//! let _g = guard!([val] sync {
//!     panic!("critical failure");
//! });
//! ```

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

impl<Context, Guard, Task, _R> CallableGuard<true, Context> for Guard
where
    Guard: FnOnce(Context) -> Task + Send + 'static,
    Task: Future<Output = _R> + Send + 'static,
    _R: Send + 'static,
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
    /// Creates a new `ContextGuard`.
    ///
    /// **Note on generics:** The seemingly unused `_R` generic parameter and the
    /// `Guard: FnOnce(Context) -> _R` trait bound are intentionally included.
    /// They act as a hint to help the compiler infer closure types.
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

/// Creates a [`ContextGuard`] object, binding it to a variable with the specified name (e.g., `_guard`).
/// Context variables specified in the macro invocation are available within and after the guard body.
///
/// **Note:** For usage with `panic!` or `loop`, see the [module-level documentation](self)
/// regarding type inference deadlocks.
#[macro_export]
macro_rules! guarded {
    ( $($tt:tt)* ) => {
        $crate::__guarded! { @parse@action $($tt)* }
    };
}

/// Creates a [`ContextGuard`] object, without binding it to a variable.
/// Context variables specified in the macro invocation are available within the guard body.
///
/// **Note:** For usage with `panic!` or `loop`, see the [module-level documentation](self)
/// regarding type inference deadlocks.
#[macro_export]
macro_rules! guard {
    ( $($tt:tt)* ) => {
        $crate::__guarded! { @parse@async action: [ @expr ] ; $($tt)* }
    };
}

// endregion

/// Alias for [`guarded!`].
///
/// **Note:** For usage with `panic!` or `loop`, see the [module-level documentation](self)
/// regarding type inference deadlocks.
#[macro_export]
macro_rules! defer {
    ( $($tt:tt)* ) => {
        $crate::guarded! { $($tt)* }
    };
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[test]
    fn trigger_sync_executes_once() {
        let called = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));

        let value = 7usize;
        let guard = {
            let called = called.clone();
            let observed = observed.clone();
            crate::guard!(move [value] {
                called.fetch_add(1, Ordering::SeqCst);
                observed.store(value, Ordering::SeqCst);
            })
        };

        guard.trigger();

        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert_eq!(observed.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn defuse_sync_returns_context_without_running_guard() {
        let called = Arc::new(AtomicUsize::new(0));

        let value = String::from("hello");
        let guard = {
            let called = called.clone();
            crate::guard!(move [mut value] {
                value.push_str(" world");
                called.fetch_add(1, Ordering::SeqCst);
            })
        };

        let context = guard.defuse();
        assert_eq!(context, "hello");
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn drop_sync_triggers_guard() {
        let called = Arc::new(AtomicUsize::new(0));

        {
            let called = called.clone();
            crate::guarded!([called] {
                called.fetch_add(1, Ordering::SeqCst);
            });
        }

        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drop_propagates_guard_panic() {
        let dropped = catch_unwind(|| {
            guarded! {
                sync {
                    panic!("boom");
                }
            }
        });

        assert!(dropped.is_err());
    }

    #[tokio::test]
    async fn trigger_async_returns_runnable_task() {
        let called = Arc::new(AtomicUsize::new(0));

        let value = 5usize;
        let guard = {
            let called = called.clone();
            crate::guard!(move [value] async move {
                called.fetch_add(value, Ordering::SeqCst);
            })
        };
        let task = guard.trigger();
        task.await;

        assert_eq!(called.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn drop_async_detaches_task() {
        let (tx, rx) = oneshot::channel();

        {
            let mut tx = Some(tx);
            let value = 9usize;
            let _guard = crate::guard!(move [value] {
                let tx = tx.take();
                async move {
                        if let Some(tx) = tx {
                            let _ = tx.send(value);
                        }
                    }
            });
        }

        let value = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("detached task should run")
            .expect("detached task should send value");
        assert_eq!(value, 9);
    }

    #[tokio::test]
    async fn defuse_async_does_not_execute() {
        let called = Arc::new(AtomicUsize::new(0));

        let value = 11usize;
        let guard = {
            let called = called.clone();
            crate::guard!(move [value] async move {
                called.fetch_add(value, Ordering::SeqCst);
            })
        };

        let context = guard.defuse();
        assert_eq!(context, 11);

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn guarded_named_mut_binding_updates_context_before_drop() {
        let committed = Arc::new(AtomicUsize::new(0));

        {
            let value = 1usize;
            let step = 2usize;
            let committed = committed.clone();

            crate::guarded!(scope_guard => [mut value, step] {
                committed.store(value + step, Ordering::SeqCst);
            });

            *value += 10;
            assert_eq!(*value, 11);
            assert_eq!(*step, 2);

            drop(scope_guard);
        }

        assert_eq!(committed.load(Ordering::SeqCst), 13);
    }

    #[test]
    fn guard_expression_parses_without_braces() {
        let observed = Arc::new(AtomicUsize::new(0));

        let value = 3usize;
        let observed_clone = observed.clone();
        let guard = crate::guard!([value] observed_clone.store(value, Ordering::SeqCst));
        guard.trigger();

        assert_eq!(observed.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn defer_alias_behaves_like_guarded_statement() {
        let called = Arc::new(AtomicUsize::new(0));

        {
            let n = 42usize;
            let called = called.clone();
            crate::defer!([n] {
                called.store(n, Ordering::SeqCst);
            });
        }

        assert_eq!(called.load(Ordering::SeqCst), 42);
    }

    #[tokio::test]
    async fn guard_and_guarded_macro_usage_matrix() {
        // 1) guard!: block body + trailing comma args + trigger()
        let sink = Arc::new(AtomicUsize::new(0));
        let v = 1usize;
        let sink_clone = sink.clone();
        let g1 = crate::guard!([v,] {
            sink_clone.store(v, Ordering::SeqCst);
        });
        g1.trigger();
        assert_eq!(sink.load(Ordering::SeqCst), 1);

        // 2) guard!: expression body (no braces)
        let sink = Arc::new(AtomicUsize::new(0));
        let sink_clone = sink.clone();
        let v = 2usize;
        let g2 = crate::guard!([v] sink_clone.store(v, Ordering::SeqCst));
        g2.trigger();
        assert_eq!(sink.load(Ordering::SeqCst), 2);

        // 3) guard!: explicit sync + no args form
        let sink = Arc::new(AtomicUsize::new(0));
        let sink_clone = sink.clone();
        let g3 = crate::guard!(sync {
            sink_clone.store(3, Ordering::SeqCst);
        });
        g3.trigger();
        assert_eq!(sink.load(Ordering::SeqCst), 3);

        // 4) guard!: move capture + defuse() prevents execution
        let sink = Arc::new(AtomicUsize::new(0));
        let owned = String::from("owned");
        let sink_clone = sink.clone();
        let g4 = crate::guard!(move [owned] {
            if owned == "owned" {
                sink_clone.store(4, Ordering::SeqCst);
            }
        });
        let context = g4.defuse();
        assert_eq!(context, "owned");
        assert_eq!(sink.load(Ordering::SeqCst), 0);

        // 5) guard!: async block inference + trigger() returns task
        let sink = Arc::new(AtomicUsize::new(0));
        let sink_clone = sink.clone();
        let n = 5usize;
        let g5 = crate::guard!([n] async move {
            sink_clone.fetch_add(n, Ordering::SeqCst);
        });
        g5.trigger().await;
        assert_eq!(sink.load(Ordering::SeqCst), 5);

        // 6) guarded!: named binding + mut arg visible outside + explicit drop
        let sink = Arc::new(AtomicUsize::new(0));
        {
            let value = 6usize;
            let delta = 1usize;
            let sink_clone = sink.clone();

            crate::guarded!(named => [mut value, delta] {
                sink_clone.store(value + delta, Ordering::SeqCst);
            });

            *value += 10;
            assert_eq!(*value, 16);
            assert_eq!(*delta, 1);
            drop(named);
        }
        assert_eq!(sink.load(Ordering::SeqCst), 17);

        // 7) guarded!: unnamed statement + expression body + implicit drop at scope end
        let sink = Arc::new(AtomicUsize::new(0));
        {
            let n = 7usize;
            let sink_clone = sink.clone();
            crate::guarded!([n] sink_clone.store(n, Ordering::SeqCst));
        }
        assert_eq!(sink.load(Ordering::SeqCst), 7);

        // 8) guarded!: explicit sync + panic path propagates on drop
        let dropped = catch_unwind(|| {
            guarded! {
                sync {
                    panic!("matrix-boom");
                }
            }
        });
        assert!(dropped.is_err());

        // 9) guarded!: async inference on drop detaches and executes
        let (tx, rx) = oneshot::channel();
        {
            let tx = Some(tx);
            crate::guarded!([mut tx] {
                let tx = tx.take();
                async move {
                    if let Some(tx) = tx {
                        let _ = tx.send(9usize);
                    }
                }
            });
        }
        let detached = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("detached task should complete")
            .expect("detached task should send value");
        assert_eq!(detached, 9);
    }
}
