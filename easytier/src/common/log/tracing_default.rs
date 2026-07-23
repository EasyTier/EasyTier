use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::{
    Metadata,
    span::{Attributes, Id, Record as SpanRecord},
    subscriber::{Interest, SetGlobalDefaultError},
};

use super::{Logger, emit_event, tracing_level};

pub(super) fn install(logger: &'static Logger) -> Result<(), SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(EventSubscriber::new(logger))
}

pub(super) struct EventSubscriber {
    logger: &'static Logger,
    next_span_id: AtomicUsize,
}

impl EventSubscriber {
    pub(super) fn new(logger: &'static Logger) -> Self {
        Self {
            logger,
            next_span_id: AtomicUsize::new(1),
        }
    }
}

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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
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
