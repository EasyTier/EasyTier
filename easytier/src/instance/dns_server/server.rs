use anyhow::{Context, Result};
use hickory_proto::rr;
use hickory_proto::rr::LowerName;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::system_conf::read_system_conf;
use hickory_server::ServerFuture;
use hickory_server::authority::{AuthorityObject, Catalog, ZoneType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::forwarder::ForwardConfig;
use hickory_server::store::{forwarder::ForwardAuthority, in_memory::InMemoryAuthority};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::common::{
    dns::{RuntimeDnsIoProvider, get_default_resolver_config},
    netns::PlatformNamespace,
};

use super::config::{GeneralConfig, Record, RunConfig};

pub struct Server {
    namespace: PlatformNamespace,
    socket_mark: Option<u32>,
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

pub fn build_authority(domain: &str, records: &[Record]) -> Result<InMemoryAuthority> {
    let zone = rr::Name::from_str(domain)?;
    let mut authority = InMemoryAuthority::empty(zone, ZoneType::Primary, false);
    for record in records.iter() {
        let r = record.try_into()?;
        authority.upsert_mut(r, 0);
    }
    Ok(authority)
}

impl Server {
    pub fn new(config: RunConfig) -> Self {
        Self::try_new(config).unwrap()
    }

    fn try_new(config: RunConfig) -> Result<Self> {
        Self::in_namespace(config, PlatformNamespace::current()?, None)
    }

    pub(crate) fn in_namespace(
        config: RunConfig,
        namespace: PlatformNamespace,
        socket_mark: Option<u32>,
    ) -> Result<Self> {
        let mut catalog = Catalog::new();
        for (domain, records) in config.zones().iter() {
            let zone = rr::Name::from_str(domain.as_str())?;
            let authroty = build_authority(domain, records)?;
            catalog.upsert(zone.clone().into(), vec![Arc::new(authroty)]);
        }

        // use forwarder authority for the root zone
        let system_conf =
            read_system_conf().unwrap_or((get_default_resolver_config(), ResolverOpts::default()));
        let forward_config = ForwardConfig {
            name_servers: system_conf
                .0
                .name_servers()
                .iter()
                .filter(|&x| {
                    !config
                        .excluded_forward_nameservers()
                        .contains(&x.socket_addr.ip())
                })
                .cloned()
                .collect::<Vec<_>>()
                .into(),
            options: Some(system_conf.1),
        };
        let auth = ForwardAuthority::builder_with_config(
            forward_config,
            GenericConnector::new(RuntimeDnsIoProvider::in_namespace(
                namespace.clone(),
                socket_mark,
            )),
        )
        .build()
        .unwrap();

        catalog.upsert(rr::Name::from_str(".")?.into(), vec![Arc::new(auth)]);

        let catalog = Arc::new(RwLock::new(catalog));
        let handler = CatalogRequestHandler::new(catalog.clone());
        let server = ServerFuture::new(handler);

        Ok(Self {
            namespace,
            socket_mark,
            server,
            catalog,
            general_config: config.general().clone(),
            udp_local_addr: None,
        })
    }

    #[cfg(test)]
    pub fn udp_local_addr(&self) -> Option<SocketAddr> {
        self.udp_local_addr
    }

    pub async fn register_udp_socket(&mut self, address: String) -> Result<SocketAddr> {
        let bind_addr = SocketAddr::from_str(&address)
            .with_context(|| format!("DNS Server failed to parse address {}", address))?;
        let socket = self.namespace.run(|| -> Result<socket2::Socket> {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(bind_addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .with_context(|| {
                format!(
                    "DNS Server failed to create UDP socket for address {}",
                    address
                )
            })?;
            socket2::SockRef::from(&socket)
                .set_reuse_address(true)
                .with_context(|| {
                    format!(
                        "DNS Server failed to set reuse address on socket {}",
                        address
                    )
                })?;
            socket.bind(&bind_addr.into()).with_context(|| {
                format!("DNS Server failed to bind socket to address {}", bind_addr)
            })?;
            socket
                .set_nonblocking(true)
                .with_context(|| "DNS Server failed to set socket to non-blocking".to_string())?;
            Ok(socket)
        })??;
        let socket = UdpSocket::from_std(socket.into()).with_context(|| {
            format!(
                "DNS Server failed to convert socket to UdpSocket for address {}",
                address
            )
        })?;

        let local_addr = socket
            .local_addr()
            .with_context(|| "DNS Server failed to get local address".to_string())?;
        self.server.register_socket(socket);

        Ok(local_addr)
    }

    async fn tcp_addresses(&self, address: &str) -> Result<Vec<SocketAddr>> {
        use easytier_core::{
            host::dns::{DnsQuery, DnsResolver},
            socket::SocketContext,
        };
        if let Ok(address) = address.parse() {
            return Ok(vec![address]);
        }
        let (host, port) = address
            .rsplit_once(':')
            .context("DNS TCP address requires a port")?;
        let port: u16 = port.parse().context("invalid DNS TCP port")?;
        let resolver = crate::common::dns::RuntimeDnsResolver::in_namespace(self.namespace.clone());
        let addresses = resolver
            .resolve(DnsQuery::new(
                host,
                SocketContext::default().with_socket_mark(self.socket_mark),
            ))
            .await?;
        anyhow::ensure!(
            !addresses.is_empty(),
            "DNS TCP address resolved to no addresses"
        );
        Ok(addresses
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    pub async fn run(&mut self) -> Result<()> {
        if let Some(address) = self.general_config.listen_tcp() {
            let mut listener = Err(std::io::Error::other(
                "DNS TCP address resolved to no addresses",
            ));
            for address in self.tcp_addresses(address).await? {
                listener = self.namespace.run(|| -> std::io::Result<_> {
                    let socket = if address.is_ipv4() {
                        TcpSocket::new_v4()?
                    } else {
                        TcpSocket::new_v6()?
                    };
                    socket.bind(address)?;
                    socket.listen(1024)
                })?;
                if listener.is_ok() {
                    break;
                }
            }
            let tcp_listener = listener
                .with_context(|| format!("DNS Server failed to bind TCP address {address}"))?;
            self.server
                .register_listener(tcp_listener, Duration::from_secs(5));
        }

        if let Some(address) = self.general_config.listen_udp() {
            let local_addr = self.register_udp_socket(address.clone()).await?;
            self.udp_local_addr = Some(local_addr);
        };

        Ok(())
    }

    #[cfg(test)]
    pub async fn shutdown(&mut self) -> Result<()> {
        self.server.shutdown_gracefully().await?;
        Ok(())
    }

    pub async fn upsert(&self, name: LowerName, authority: Arc<dyn AuthorityObject>) {
        self.catalog.write().await.upsert(name, vec![authority]);
    }

    pub async fn read_catalog(&self) -> RwLockReadGuard<'_, Catalog> {
        self.catalog.read().await
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
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn namespace_dns_listeners_and_udp_tcp_queries_stay_in_their_domain() -> Result<()> {
        use crate::common::netns::isolated_namespace_for_test;
        use hickory_proto::xfer::Protocol;
        use hickory_resolver::{
            Resolver,
            config::{NameServerConfig, ResolverConfig},
        };
        let a = isolated_namespace_for_test()?;
        let b = isolated_namespace_for_test()?;
        let address = "127.0.0.1:6053";
        let config = |ip: &str| -> Result<RunConfig> {
            Ok(RunConfigBuilder::default().general(GeneralConfigBuilder::default().listen_udp(address).listen_tcp(address).build()?)
                .zones(hashmap! { "et.internal.".to_owned() => vec![
                    RecordBuilder::default().rr_type(RecordType::A).name("www.et.internal.".to_owned()).value(ip.to_owned()).ttl(Duration::from_secs(60)).build()?,
                    RecordBuilder::default().rr_type(RecordType::SOA).name("et.internal.".to_owned()).value("ns.et.internal. hostmaster.et.internal. 2023101001 7200 3600 1209600 86400".to_owned()).ttl(Duration::from_secs(60)).build()?,
                ] }).build()?)
        };
        let mut sa = Server::in_namespace(config("192.0.2.1")?, a.platform().clone(), None)?;
        let mut sb = Server::in_namespace(config("192.0.2.2")?, b.platform().clone(), None)?;
        sa.run().await?;
        sb.run().await?;
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            for (namespace, ip) in [(&a, "192.0.2.1"), (&b, "192.0.2.2")] {
                let mut resolver_config = ResolverConfig::new();
                resolver_config.add_name_server(NameServerConfig::new(address.parse()?, protocol));
                let provider = GenericConnector::new(RuntimeDnsIoProvider::in_namespace(
                    namespace.platform().clone(),
                    None,
                ));
                let resolver = Resolver::builder_with_config(resolver_config, provider).build();
                let lookup = tokio::time::timeout(
                    Duration::from_secs(3),
                    resolver.ipv4_lookup("www.et.internal."),
                )
                .await??;
                assert_eq!(
                    lookup.iter().next().unwrap().0,
                    ip.parse::<std::net::Ipv4Addr>()?
                );
            }
        }
        sa.shutdown().await?;
        sb.shutdown().await?;
        Ok(())
    }
}
