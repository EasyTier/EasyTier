use std::marker::PhantomData;

use crate::connectivity::hole_punch::tcp::TcpHolePunchHost;

use super::TcpHolePunchRuntimeInputs;

pub(in crate::instance) struct TcpHolePunchRuntime<H> {
    host: PhantomData<fn() -> H>,
}

impl<H> TcpHolePunchRuntime<H>
where
    H: TcpHolePunchHost,
{
    pub(in crate::instance) fn new(_inputs: TcpHolePunchRuntimeInputs<H>) -> Self {
        Self { host: PhantomData }
    }

    pub(in crate::instance) fn run(&self) {}

    pub(in crate::instance) async fn stop(&self) {}
}
