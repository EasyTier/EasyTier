use crate::dns::config::zone::Fallthrough;
use delegate::delegate;
use derive_more::{Constructor, Deref, DerefMut};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{LowerName, RecordType, TSigResponseContext};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
};
use std::collections::HashSet;
use std::sync::Arc;

pub type ArcZoneHandler = Arc<dyn ZoneHandler>;

#[derive(Constructor, Deref, DerefMut)]
pub struct ChainedZoneHandler<H>
where
    H: ZoneHandler,
{
    #[deref]
    #[deref_mut]
    handler: H,
    fallthrough: HashSet<Fallthrough>,
}

#[async_trait::async_trait]
impl<H> ZoneHandler for ChainedZoneHandler<H>
where
    H: ZoneHandler,
{
    delegate! {
        to self.handler {
            fn zone_type(&self) -> ZoneType;
            fn axfr_policy(&self) -> AxfrPolicy;
            fn origin(&self) -> &LowerName;
        }
    }

    #[inline]
    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        self.handler.update(update, now).await
    }
    #[inline]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.handler
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }
    #[inline]
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let (result, tsig) = self.handler.search(request, lookup_options).await;

        match &result {
            LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e))
                if self.fallthrough.contains(&Fallthrough::Any)
                    || matches!(e, LookupError::ResponseCode(c) if self.fallthrough.contains(&(*c).into())) =>
            {
                (LookupControlFlow::Skip, None)
            }
            _ => (result, tsig),
        }
    }
    #[inline]
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.handler.nsec_records(name, lookup_options).await
    }
}
