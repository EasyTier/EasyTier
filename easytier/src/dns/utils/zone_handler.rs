use delegate::delegate;
use derive_more::{Deref, DerefMut, From};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{LowerName, RecordType, TSigResponseContext};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
};
use std::sync::Arc;

pub type ArcZoneHandler = Arc<dyn ZoneHandler>;

pub trait LookupControlFlowExt {
    fn skip_negative(self) -> Self;
}

impl LookupControlFlowExt for LookupControlFlow<AuthLookup> {
    fn skip_negative(self) -> Self {
        match self {
            Self::Continue(e) | Self::Break(e) if matches!(e, Err(LookupError::NameExists)) => {
                Self::Continue(Ok(Default::default()))
            }
            Self::Continue(Err(_)) | Self::Break(Err(_)) => Self::Skip,
            other => other,
        }
    }
}

#[derive(From, Deref, DerefMut)]
pub struct ChainedZoneHandler<H>(H)
where
    H: ZoneHandler;

#[async_trait::async_trait]
impl<H> ZoneHandler for ChainedZoneHandler<H>
where
    H: ZoneHandler,
{
    delegate! {
        to self.0 {
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
        self.0.update(update, now).await
    }
    #[inline]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.0
            .lookup(name, rtype, request_info, lookup_options)
            .await
            .skip_negative()
    }
    #[inline]
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<AuthLookup>,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let result = if let Some(Ok(l)) = last_result.map_result() {
            LookupControlFlow::Break(Ok(l))
        } else {
            self.0
                .lookup(name, rtype, request_info, lookup_options)
                .await
                .skip_negative()
        };
        (result, None)
    }
    #[inline]
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let (result, tsig) = self.0.search(request, lookup_options).await;
        (result.skip_negative(), tsig)
    }
    #[inline]
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.0.nsec_records(name, lookup_options).await
    }
}
