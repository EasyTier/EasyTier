#[cfg(not(any(feature = "tracing", feature = "profiling")))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(any(feature = "tracing", feature = "profiling"))]
use tracing::{Event, subscriber::SetGlobalDefaultError};
#[cfg(not(any(feature = "tracing", feature = "profiling")))]
use tracing::{
    Metadata,
    span::{Attributes, Id, Record as SpanRecord},
    subscriber::{Interest, SetGlobalDefaultError},
};
#[cfg(any(feature = "tracing", feature = "profiling"))]
use tracing_subscriber::prelude::*;

#[cfg(not(any(feature = "tracing", feature = "profiling")))]
use super::tracing_level;
use super::{Logger, emit_event};

#[cfg(not(any(feature = "tracing", feature = "profiling")))]
pub(super) fn install(logger: &'static Logger) -> Result<(), SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(EventSubscriber::new(logger))
}

#[cfg(any(feature = "tracing", feature = "profiling"))]
pub(super) fn install(logger: &'static Logger) -> Result<(), SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(layered_subscriber(logger))
}

#[cfg(any(feature = "tracing", feature = "profiling"))]
fn layered_subscriber(logger: &'static Logger) -> impl tracing::Subscriber {
    let subscriber = tracing_subscriber::registry();
    #[cfg(feature = "tracing")]
    let subscriber = subscriber.with(console_subscriber::ConsoleLayer::builder().spawn());
    #[cfg(feature = "lttng")]
    let subscriber = subscriber.with(easytier_profiling::lttng::LttngLayer.with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() == "easytier::profiling"
        }),
    ));
    // Do not globally filter the registry by log level: profiling spans are TRACE.
    subscriber.with(
        EventLayer(logger).with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() != "easytier::profiling"
        })),
    )
}

#[cfg(any(feature = "tracing", feature = "profiling"))]
struct EventLayer(&'static Logger);

#[cfg(any(feature = "tracing", feature = "profiling"))]
impl<S> tracing_subscriber::Layer<S> for EventLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        emit_event(self.0, event);
    }
}

#[cfg(not(any(feature = "tracing", feature = "profiling")))]
pub(super) struct EventSubscriber {
    logger: &'static Logger,
    next_span_id: AtomicUsize,
}

#[cfg(not(any(feature = "tracing", feature = "profiling")))]
impl EventSubscriber {
    pub(super) fn new(logger: &'static Logger) -> Self {
        Self {
            logger,
            next_span_id: AtomicUsize::new(1),
        }
    }
}

#[cfg(not(any(feature = "tracing", feature = "profiling")))]
impl tracing::Subscriber for EventSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event()
            && self
                .logger
                .enabled(metadata.target(), tracing_level(metadata.level()))
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        let id = self
            .next_span_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                Some(if id == usize::MAX { 1 } else { id + 1 })
            })
            .expect("span id update always succeeds");
        Id::from_u64(id as u64)
    }

    fn record(&self, _span: &Id, _values: &SpanRecord<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        emit_event(self.logger, event);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if metadata.is_event() {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        if self.logger.file.dynamic() {
            return Some(tracing::level_filters::LevelFilter::TRACE);
        }
        Some(match self.logger.max_level() {
            log::LevelFilter::Off => tracing::level_filters::LevelFilter::OFF,
            log::LevelFilter::Error => tracing::level_filters::LevelFilter::ERROR,
            log::LevelFilter::Warn => tracing::level_filters::LevelFilter::WARN,
            log::LevelFilter::Info => tracing::level_filters::LevelFilter::INFO,
            log::LevelFilter::Debug => tracing::level_filters::LevelFilter::DEBUG,
            log::LevelFilter::Trace => tracing::level_filters::LevelFilter::TRACE,
        })
    }

    fn clone_span(&self, id: &Id) -> Id {
        id.clone()
    }

    fn try_close(&self, _id: Id) -> bool {
        true
    }
}

#[cfg(all(test, feature = "lttng", not(feature = "tracing")))]
mod tests {
    #[test]
    fn disabled_text_logging_does_not_disable_profiling() {
        use crate::common::log::{Logger, TargetFilter, file::FileSink};
        let logger = Box::leak(Box::new(Logger::new(
            TargetFilter::console(Some(log::LevelFilter::Off)).unwrap(),
            FileSink::disabled(),
        )));
        tracing::subscriber::with_default(super::layered_subscriber(logger), || {
            assert!(tracing::enabled!(target: "easytier::profiling", tracing::Level::TRACE));
            let span = tracing::trace_span!(target: "easytier::profiling", "test");
            assert!(!span.is_disabled());
            span.in_scope(|| easytier_profiling::event!("test", value = 1));
        });
    }
}
