//! A composable tracing layer. Filtering belongs on this layer, not the registry.
use std::fmt::Write as _;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

// The pinned generator emits unannotated pointer transmutes; keep its lint
// exception scoped to generated code rather than the tracing adapter.
#[allow(clippy::missing_transmute_annotations)]
mod tracepoints {
    include!(concat!(env!("OUT_DIR"), "/tracepoints.rs"));
}
use tracepoints::easytier as tp;

#[derive(Default)]
struct Fields(String);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

/// Emits span lifetime and poll boundaries separately; no clock or TLS timing stack.
#[derive(Default)]
pub struct LttngLayer;
impl<S> Layer<S> for LttngLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let parent = ctx
            .span(id)
            .and_then(|span| span.parent().map(|p| p.id().into_u64()))
            .unwrap_or(0);
        tp::span_new(
            id.into_u64(),
            parent,
            attrs.metadata().name(),
            attrs.metadata().target(),
            &fields.0,
        );
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        values.record(&mut fields);
        tp::span_record(id.into_u64(), &fields.0);
    }
    fn on_enter(&self, id: &Id, _ctx: Context<'_, S>) {
        tp::span_enter(id.into_u64());
    }
    fn on_exit(&self, id: &Id, _ctx: Context<'_, S>) {
        tp::span_exit(id.into_u64());
    }
    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        tp::span_close(id.into_u64());
    }
    fn on_follows_from(&self, id: &Id, follows: &Id, _ctx: Context<'_, S>) {
        tp::span_follows_from(id.into_u64(), follows.into_u64());
    }
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let parent = ctx
            .event_span(event)
            .map(|span| span.id().into_u64())
            .unwrap_or(0);
        let metadata = event.metadata();
        tp::event(
            parent,
            metadata.name(),
            metadata.target(),
            metadata.level().as_str(),
            &fields.0,
        );
    }
}
