use anyhow::Result;
use hickory_proto::op::{Edns, MessageType};
use hickory_proto::rr;
use hickory_proto::rr::LowerName;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_server::authority::{AuthorityObject, Catalog, UpdateRequest, ZoneType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::forwarder::ForwardConfig;
use hickory_server::store::{forwarder::ForwardAuthority, in_memory::InMemoryAuthority};
use hickory_server::ServerFuture;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::common::stun::get_default_resolver_config;

use super::config::{GeneralConfig, RunConfig};

static ET_DNS_ZONE: &str = "et.net.";

pub struct Server {
    server: ServerFuture<CatalogRequestHandler>,
    catalog: Arc<RwLock<Catalog>>,
    general_config: GeneralConfig,
    udp_local_addr: Option<SocketAddr>,
}

struct CatalogRequestHandler {
    catalog: Arc<RwLock<Catalog>>,
}

impl CatalogRequestHandler {
    fn new(catalog: Arc<RwLock<Catalog>>) -> CatalogRequestHandler {
        // let system_conf = read_system_conf();
        // let recursor = match system_conf {
        //     Ok((conf, _)) => RecursorBuilder::default().build(conf),
        //     Err(_) => RecursorBuilder::default().build(get_default_resolver_config()),
        // }
        // // policy is security unware, this will never return an error
        // .unwrap();

        Self { catalog }
    }

    fn is_et_zone_query(&self, request: &Request) -> bool {
        if request.message_type() != MessageType::Query {
            return false;
        }

        let Ok(zone) = request.zone() else {
            return false;
        };

        if !zone
            .name()
            .zone_of(&LowerName::from_str(ET_DNS_ZONE).unwrap())
        {
            return false;
        }

        true
    }
}

#[async_trait::async_trait]
impl RequestHandler for CatalogRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.catalog
            .read()
            .await
            .handle_request(request, response_handle)
            .await
    }
}

impl Server {
    pub fn new(config: RunConfig) -> Self {
        Self::try_new(config).unwrap()
    }

    fn try_new(config: RunConfig) -> Result<Self> {
        let mut catalog = Catalog::new();
        for (domain, records) in config.zones().iter() {
            let zone = rr::Name::from_str(domain.as_str())?;
            let mut authorities = InMemoryAuthority::empty(zone.clone(), ZoneType::Primary, false);
            for record in records.iter() {
                let r = record.try_into()?;
                authorities.upsert_mut(r, 0);
            }
            catalog.upsert(zone.clone().into(), vec![Arc::new(authorities)]);
        }

        // use forwarder authority for the root zone
        let system_conf =
            read_system_conf().unwrap_or((get_default_resolver_config(), ResolverOpts::default()));
        let forward_config = ForwardConfig {
            name_servers: system_conf
                .0
                .name_servers()
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .into(),
            options: Some(system_conf.1),
        };
        let auth = ForwardAuthority::builder_with_config(
            forward_config,
            TokioConnectionProvider::default(),
        )
        .build()
        .unwrap();

        catalog.upsert(rr::Name::from_str(".")?.into(), vec![Arc::new(auth)]);

        let catalog = Arc::new(RwLock::new(catalog));
        let handler = CatalogRequestHandler::new(catalog.clone());
        let server = ServerFuture::new(handler);

        Ok(Self {
            server,
            catalog,
            general_config: config.general().clone(),
            udp_local_addr: None,
        })
    }

    pub fn udp_local_addr(&mut self) -> Option<SocketAddr> {
        self.udp_local_addr
    }

    pub async fn run(&mut self) -> Result<()> {
        if let Some(address) = self.general_config.listen_udp() {
            let socket = UdpSocket::bind(address).await?;
            self.udp_local_addr = Some(socket.local_addr()?);
            self.server.register_socket(socket);
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.server.shutdown_gracefully().await?;
        Ok(())
    }

    pub async fn upsert(&self, name: LowerName, authority: Box<dyn AuthorityObject>) {
        self.catalog
            .write()
            .await
            .upsert(name, vec![authority.into()]);
    }

    pub async fn remove(&self, name: &LowerName) -> Option<Vec<Arc<dyn AuthorityObject>>> {
        self.catalog.write().await.remove(name)
    }

    pub async fn update<R: ResponseHandler>(
        &self,
        update: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> io::Result<ResponseInfo> {
        self.catalog
            .write()
            .await
            .update(update, response_edns, response_handle)
            .await
    }

    pub async fn contains(&self, name: &LowerName) -> bool {
        self.catalog.read().await.contains(name)
    }

    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> ResponseInfo {
        self.catalog
            .read()
            .await
            .lookup(request, response_edns, response_handle)
            .await
    }

    pub async fn read_catalog(&self) -> RwLockReadGuard<'_, Catalog> {
        self.catalog.read().await
    }

    pub async fn write_catalog(&self) -> RwLockWriteGuard<'_, Catalog> {
        self.catalog.write().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::dns_server::config::{
        GeneralConfigBuilder, RecordBuilder, RecordType, RunConfigBuilder,
    };
    use anyhow::Result;
    use hickory_client::client::{Client, ClientHandle};
    use hickory_proto::rr;
    use hickory_proto::runtime::TokioRuntimeProvider;
    use hickory_proto::udp::UdpClientStream;
    use maplit::hashmap;
    use std::time::Duration;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let mut server = Server::new(
            RunConfigBuilder::default()
                .general(GeneralConfigBuilder::default().build()?)
                .build()?,
        );
        server.run().await?;
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn can_resolve_records() -> Result<()> {
        let configured_record = RecordBuilder::default()
            .rr_type(RecordType::A)
            .name("www.et.internal.".to_string())
            .value("123.123.123.123".to_string())
            .ttl(Duration::from_secs(60))
            .build()?;
        let configured_record2 = RecordBuilder::default()
            .rr_type(RecordType::A)
            .name("中文.et.internal.".to_string())
            .value("123.123.123.123".to_string())
            .ttl(Duration::from_secs(60))
            .build()?;
        let soa_record = RecordBuilder::default()
            .rr_type(RecordType::SOA)
            .name("et.internal.".to_string())
            .value(
                "ns.et.internal. hostmaster.et.internal. 2023101001 7200 3600 1209600 86400"
                    .to_string(),
            )
            .ttl(Duration::from_secs(60))
            .build()?;
        let config = RunConfigBuilder::default()
            .general(
                GeneralConfigBuilder::default()
                    .listen_udp("127.0.0.1:0")
                    .build()?,
            )
            .zones(hashmap! {
                "et.internal.".to_string() => vec![configured_record.clone(), soa_record.clone(), configured_record2.clone()],
            })
            .build()?;

        let mut server = Server::new(config);
        server.run().await?;

        let local_addr = server.udp_local_addr().unwrap();
        let stream = UdpClientStream::builder(local_addr, TokioRuntimeProvider::default()).build();
        let (mut client, background) = Client::connect(stream).await?;
        let background_task = tokio::spawn(background);
        let response = client
            .query(
                rr::Name::from_str("www.et.internal")?,
                rr::DNSClass::IN,
                rr::RecordType::A,
            )
            .await?;
        drop(background_task);

        println!("Response: {:?}", response);

        assert_eq!(response.answers().len(), 1);
        let expected_record: rr::Record = configured_record.try_into()?;
        assert_eq!(response.answers().first().unwrap(), &expected_record);

        server.shutdown().await?;
        Ok(())
    }
}
