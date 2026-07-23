use tracing::{Event, subscriber::SetGlobalDefaultError};
use tracing_subscriber::prelude::*;

use super::{Logger, emit_event};

pub(super) fn install(logger: &'static Logger) -> Result<(), SetGlobalDefaultError> {
    let subscriber = tracing_subscriber::registry()
        .with(console_subscriber::ConsoleLayer::builder().spawn())
        .with(EventLayer(logger));
    tracing::subscriber::set_global_default(subscriber)
}

struct EventLayer(&'static Logger);

impl<S> tracing_subscriber::Layer<S> for EventLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        emit_event(self.0, event);
    }
}
