use derive_more::{Deref, DerefMut, From};
use hickory_proto::rr::{LowerName, RecordType};
use hickory_server::authority::{
    Authority, AuthorityObject, LookupControlFlow, LookupObject, LookupOptions, MessageRequest,
    UpdateResult, ZoneType,
};
use hickory_server::server::RequestInfo;
use std::sync::Arc;

pub type ArcAuthority = Arc<dyn AuthorityObject>;

#[derive(From, Deref, DerefMut)]
pub struct ChainedAuthority<A>(A)
where
    A: Authority,
    A::Lookup: LookupObject + 'static;

#[async_trait::async_trait]
impl<A> Authority for ChainedAuthority<A>
where
    A: Authority,
    A::Lookup: LookupObject + 'static,
{
    type Lookup = A::Lookup;

    #[inline]
    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }
    #[inline]
    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
    }
    #[inline]
    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.0.update(update).await
    }
    #[inline]
    fn origin(&self) -> &LowerName {
        self.0.origin()
    }
    #[inline]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.lookup(name, rtype, lookup_options).await
    }
    #[inline]
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        if let Some(Ok(l)) = last_result.map_result() {
            LookupControlFlow::Break(Ok(l))
        } else {
            self.0
                .lookup(name, rtype, lookup_options)
                .await
                .map(|l| Box::new(l) as _)
        }
    }
    #[inline]
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.search(request_info, lookup_options).await
    }
    #[inline]
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.get_nsec_records(name, lookup_options).await
    }
}
