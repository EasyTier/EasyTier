use easytier_profiling as profiling;

#[profiling::instrument]
fn sync_result(value: u32) -> Result<u32, &'static str> {
    if value == 0 {
        return Err("zero");
    }
    Ok(value + 1)
}

struct Worker;
impl Worker {
    #[profiling::instrument("Worker::run")]
    async fn run(&self, value: u32) -> Result<u32, &'static str> {
        tokio::task::yield_now().await;
        Ok(sync_result(value)? + 1)
    }
}

#[test]
fn sync_control_flow() {
    assert_eq!(sync_result(0), Err("zero"));
    assert_eq!(sync_result(1), Ok(2));
    assert_eq!(profiling::scope!("block", 42), 42);
    profiling::event!("packet", bytes = 42, accepted = true);
}

#[tokio::test]
async fn async_control_flow_and_send() {
    fn assert_send(_: impl Send) {}
    assert_send(Worker.run(1));
    assert_eq!(Worker.run(1).await, Ok(3));
    assert_eq!(Worker.run(0).await, Err("zero"));
    assert_eq!(profiling::future!(async { 7 }).await, 7);
}

#[tokio::test]
async fn channel_and_locks_preserve_operations() {
    let mut calls = 0;
    let (tx, mut rx): (
        profiling::wrap::tokio::sync::mpsc::Sender<u32>,
        profiling::wrap::tokio::sync::mpsc::Receiver<u32>,
    ) = profiling::channel!({
        calls += 1;
        tokio::sync::mpsc::channel(2)
    });
    assert_eq!(calls, 1);
    tx.try_send(1).unwrap();
    tx.send(2).await.unwrap();
    assert_eq!(rx.try_recv().unwrap(), 1);
    assert_eq!(rx.recv().await, Some(2));
    drop(tx);
    assert_eq!(rx.recv().await, None);

    let lock: profiling::wrap::parking_lot::RwLock<u32> =
        profiling::rw_lock!(parking_lot::RwLock::new(3));
    *lock.write() = 4;
    assert_eq!(*lock.read(), 4);
    let mutex: profiling::wrap::tokio::sync::Mutex<u32> =
        profiling::mutex!(tokio::sync::Mutex::new(5));
    assert_eq!(*mutex.lock().await, 5);
}

#[cfg(not(feature = "hotpath"))]
#[test]
fn specialized_options_are_not_evaluated() {
    let mut evaluations = 0;
    let value = profiling::mutex!(
        {
            evaluations += 1;
            std::sync::Mutex::new(3)
        },
        label = panic!("disabled option")
    );
    assert_eq!(evaluations, 1);
    assert_eq!(*value.lock().unwrap(), 3);
}

#[cfg(not(any(feature = "hotpath", feature = "tracing")))]
#[test]
fn disabled_events_and_labels_are_not_evaluated() {
    profiling::event!("disabled", value = panic!("disabled event"));
    assert_eq!(profiling::scope!(panic!("disabled label"), 3), 3);
}

#[cfg(feature = "tracing")]
mod tracing_tests {
    use super::*;
    use std::{
        collections::HashMap,
        future::Future,
        pin::pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Wake, Waker},
    };
    use tracing::{Subscriber, span::Id};
    use tracing_subscriber::{Layer, layer, prelude::*};

    #[derive(Default, Debug)]
    struct State {
        active: i32,
        enters: usize,
        exits: usize,
        closes: usize,
        names: HashMap<u64, String>,
        parents: Vec<(String, Option<String>)>,
        events: usize,
    }
    struct Recorder(Arc<Mutex<State>>);
    impl<S> Layer<S> for Recorder
    where
        S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &Id,
            ctx: layer::Context<'_, S>,
        ) {
            let mut state = self.0.lock().unwrap();
            let name = attrs.metadata().name().to_owned();
            let parent = ctx
                .span(id)
                .and_then(|s| s.parent().map(|p| p.name().to_owned()));
            state.parents.push((name.clone(), parent));
            state.names.insert(id.into_u64(), name);
        }
        fn on_enter(&self, _: &Id, _: layer::Context<'_, S>) {
            let mut state = self.0.lock().unwrap();
            state.active += 1;
            state.enters += 1;
        }
        fn on_exit(&self, _: &Id, _: layer::Context<'_, S>) {
            let mut state = self.0.lock().unwrap();
            state.active -= 1;
            state.exits += 1;
        }
        fn on_close(&self, _: Id, _: layer::Context<'_, S>) {
            self.0.lock().unwrap().closes += 1;
        }
        fn on_event(&self, _: &tracing::Event<'_>, _: layer::Context<'_, S>) {
            self.0.lock().unwrap().events += 1;
        }
    }
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[test]
    fn pending_future_exits_and_cancellation_closes_span() {
        let state = Arc::new(Mutex::new(State::default()));
        let subscriber = tracing_subscriber::registry().with(Recorder(state.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let waker = Waker::from(Arc::new(NoopWake));
            let mut cx = Context::from_waker(&waker);
            {
                let mut future = pin!(Worker.run(1));
                assert!(future.as_mut().poll(&mut cx).is_pending());
                assert_eq!(state.lock().unwrap().active, 0);
                assert_eq!(state.lock().unwrap().closes, 0);
            }
            assert_eq!(state.lock().unwrap().closes, 1);
            {
                let mut future = pin!(Worker.run(1));
                assert!(future.as_mut().poll(&mut cx).is_pending());
                assert_eq!(future.as_mut().poll(&mut cx), Poll::Ready(Ok(3)));
            }
            profiling::event!("packet", bytes = 42);
        });
        let state = state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.enters, state.exits);
        assert_eq!(state.closes, 3);
        assert_eq!(state.events, 1);
        assert!(state.parents.iter().any(|(name, parent)| {
            name.ends_with("sync_result") && parent.as_deref() == Some("Worker::run")
        }));
    }

    #[cfg(feature = "lttng")]
    #[test]
    fn lttng_layer_composes_with_other_consumers() {
        let state = Arc::new(Mutex::new(State::default()));
        let subscriber =
            tracing_subscriber::registry()
                .with(profiling::lttng::LttngLayer.with_filter(
                    tracing_subscriber::filter::filter_fn(|m| m.target() == "easytier::profiling"),
                ))
                .with(Recorder(state.clone()));
        tracing::subscriber::with_default(subscriber, || {
            profiling::scope!("lttng_test", profiling::event!("packet", bytes = 1));
            tracing::info!(target: "normal_log", "still enabled");
            let span = tracing::trace_span!(target: "easytier::profiling", "record", value = tracing::field::Empty);
            span.record("value", 7);
            let linked = tracing::trace_span!(target: "easytier::profiling", "linked");
            linked.follows_from(span.id());
        });
        let state = state.lock().unwrap();
        assert_eq!(state.events, 2);
        assert_eq!(state.closes, 3);
    }
}
