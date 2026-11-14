use std::{
    collections::HashMap,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use zbus::{
    DBusError,
    blocking::{Connection, connection::Builder},
    fdo,
    message::{Flags, Header},
    zvariant::OwnedObjectPath,
};

pub const AF_INET: i32 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixtureConfig {
    pub nameservers: Vec<(i32, Vec<u8>)>,
    pub domains: Vec<(String, bool)>,
    pub default_route: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum FixtureFailure {
    LinkBusy,
    AccessDenied,
    UnknownMethod,
    Delay(Duration),
    Wait,
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "org.freedesktop.resolve1")]
enum FixtureError {
    LinkBusy(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

#[derive(Default)]
struct FixtureState {
    config: Mutex<FixtureConfig>,
    calls: Mutex<Vec<String>>,
    failures: Mutex<HashMap<String, FixtureFailure>>,
    default_route_property: AtomicBool,
    interactive: AtomicBool,
    wait: (AtomicBool, tokio::sync::Notify),
}

impl FixtureState {
    async fn write(
        &self,
        service: &str,
        method: &str,
        header: &Header<'_>,
        update: impl FnOnce(&mut FixtureConfig) + Send,
    ) -> Result<(), FixtureError> {
        let key = format!("{service}.{method}");
        self.calls.lock().unwrap().push(key.clone());
        self.interactive.fetch_or(
            header
                .primary()
                .flags()
                .contains(Flags::AllowInteractiveAuth),
            Ordering::SeqCst,
        );
        let failure = self.failures.lock().unwrap().get(&key).copied();
        if matches!(
            failure,
            Some(FixtureFailure::Delay(_) | FixtureFailure::Wait)
        ) {
            self.failures.lock().unwrap().remove(&key);
        }
        match failure {
            Some(FixtureFailure::LinkBusy) => {
                return Err(FixtureError::LinkBusy("link is managed".to_owned()));
            }
            Some(FixtureFailure::AccessDenied) => {
                return Err(FixtureError::ZBus(zbus::Error::FDO(Box::new(
                    fdo::Error::AccessDenied("non-interactive authorization denied".to_owned()),
                ))));
            }
            Some(FixtureFailure::UnknownMethod) => {
                return Err(FixtureError::ZBus(zbus::Error::FDO(Box::new(
                    fdo::Error::UnknownMethod(format!("{method} is unavailable")),
                ))));
            }
            Some(FixtureFailure::Delay(delay)) => {
                let timer = Arc::new(tokio::sync::Notify::new());
                let wake = timer.clone();
                thread::spawn(move || {
                    thread::sleep(delay);
                    wake.notify_one();
                });
                timer.notified().await;
                update(&mut self.config.lock().unwrap());
                return Ok(());
            }
            Some(FixtureFailure::Wait) => {
                loop {
                    let notified = self.wait.1.notified();
                    if self.wait.0.load(Ordering::SeqCst) {
                        break;
                    }
                    notified.await;
                }
                update(&mut self.config.lock().unwrap());
                return Ok(());
            }
            None => {}
        }
        update(&mut self.config.lock().unwrap());
        Ok(())
    }
}

struct ResolvedManagerFixture {
    state: Arc<FixtureState>,
    ifindex: i32,
}

#[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
impl ResolvedManagerFixture {
    fn get_link(&self, ifindex: i32) -> fdo::Result<OwnedObjectPath> {
        assert_eq!(ifindex, self.ifindex);
        OwnedObjectPath::try_from(format!("/org/freedesktop/resolve1/link/_{ifindex}"))
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(name = "SetLinkDNS")]
    async fn set_link_dns(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("resolved", "SetLinkDNS", &header, |config| {
                config.nameservers = addresses;
            })
            .await
    }

    #[zbus(name = "SetLinkDomains")]
    async fn set_link_domains(
        &self,
        ifindex: i32,
        domains: Vec<(String, bool)>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("resolved", "SetLinkDomains", &header, |config| {
                config.domains = domains;
            })
            .await
    }

    #[zbus(name = "SetLinkDefaultRoute")]
    async fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("resolved", "SetLinkDefaultRoute", &header, |config| {
                config.default_route = enable;
            })
            .await
    }
}

struct NetworkManagerFixture {
    state: Arc<FixtureState>,
    ifindex: i32,
}

#[zbus::interface(name = "org.freedesktop.network1.Manager")]
impl NetworkManagerFixture {
    #[zbus(name = "SetLinkDNS")]
    async fn set_link_dns(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("networkd", "SetLinkDNS", &header, |config| {
                config.nameservers = addresses;
            })
            .await
    }

    #[zbus(name = "SetLinkDomains")]
    async fn set_link_domains(
        &self,
        ifindex: i32,
        domains: Vec<(String, bool)>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("networkd", "SetLinkDomains", &header, |config| {
                config.domains = domains;
            })
            .await
    }

    #[zbus(name = "SetLinkDefaultRoute")]
    async fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FixtureError> {
        assert_eq!(ifindex, self.ifindex);
        self.state
            .write("networkd", "SetLinkDefaultRoute", &header, |config| {
                config.default_route = enable;
            })
            .await
    }
}

struct LinkFixture {
    state: Arc<FixtureState>,
}

#[zbus::interface(name = "org.freedesktop.resolve1.Link")]
impl LinkFixture {
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> Vec<(i32, Vec<u8>)> {
        self.state.config.lock().unwrap().nameservers.clone()
    }

    #[zbus(property)]
    fn domains(&self) -> Vec<(String, bool)> {
        self.state.config.lock().unwrap().domains.clone()
    }

    #[zbus(property)]
    fn default_route(&self) -> fdo::Result<bool> {
        if !self.state.default_route_property.load(Ordering::SeqCst) {
            return Err(fdo::Error::UnknownProperty(
                "DefaultRoute is unavailable".to_owned(),
            ));
        }
        Ok(self.state.config.lock().unwrap().default_route)
    }
}

struct BusDaemon {
    child: Child,
    _directory: TempDir,
}

impl BusDaemon {
    fn start() -> (Self, String) {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("bus.sock");
        let address = format!("unix:path={}", socket.display());
        let child = Command::new("dbus-daemon")
            .arg("--session")
            .arg("--nofork")
            .arg("--nopidfile")
            .arg("--address")
            .arg(&address)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut daemon = Self {
            child,
            _directory: directory,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!("private dbus-daemon exited early: {status}");
            }
            assert!(Instant::now() < deadline, "private D-Bus did not start");
            thread::sleep(Duration::from_millis(10));
        }
        (daemon, address)
    }
}

impl Drop for BusDaemon {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

pub struct ResolvedFixture {
    pub address: String,
    state: Arc<FixtureState>,
    ifindex: i32,
    resolved: Option<Connection>,
    _networkd: Connection,
    _daemon: BusDaemon,
}

impl ResolvedFixture {
    fn resolved_connection(address: &str, state: &Arc<FixtureState>, ifindex: i32) -> Connection {
        let link_path = format!("/org/freedesktop/resolve1/link/_{ifindex}");
        Builder::address(address)
            .unwrap()
            .name("org.freedesktop.resolve1")
            .unwrap()
            .serve_at(
                "/org/freedesktop/resolve1",
                ResolvedManagerFixture {
                    state: state.clone(),
                    ifindex,
                },
            )
            .unwrap()
            .serve_at(
                link_path,
                LinkFixture {
                    state: state.clone(),
                },
            )
            .unwrap()
            .build()
            .unwrap()
    }

    pub fn start() -> Self {
        let (daemon, address) = BusDaemon::start();
        let state = Arc::new(FixtureState::default());
        state.default_route_property.store(true, Ordering::SeqCst);
        let ifindex = i32::try_from(nix::net::if_::if_nametoindex("lo").unwrap()).unwrap();
        let resolved = Self::resolved_connection(&address, &state, ifindex);
        let networkd = Builder::address(address.as_str())
            .unwrap()
            .name("org.freedesktop.network1")
            .unwrap()
            .serve_at(
                "/org/freedesktop/network1",
                NetworkManagerFixture {
                    state: state.clone(),
                    ifindex,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        Self {
            address,
            state,
            ifindex,
            resolved: Some(resolved),
            _networkd: networkd,
            _daemon: daemon,
        }
    }

    fn restart_resolved_with_state(&mut self, preserve_config: bool) {
        let resolved = self.resolved.take().unwrap();
        resolved.release_name("org.freedesktop.resolve1").unwrap();
        drop(resolved);
        if !preserve_config {
            *self.state.config.lock().unwrap() = FixtureConfig {
                default_route: true,
                ..Default::default()
            };
        }
        self.resolved = Some(Self::resolved_connection(
            &self.address,
            &self.state,
            self.ifindex,
        ));
    }

    pub fn restart_resolved(&mut self) {
        self.restart_resolved_with_state(false);
    }

    pub fn restart_resolved_preserving_config(&mut self) {
        self.restart_resolved_with_state(true);
    }

    pub fn config(&self) -> FixtureConfig {
        self.state.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: FixtureConfig) {
        *self.state.config.lock().unwrap() = config;
    }

    pub fn calls(&self) -> Vec<String> {
        self.state.calls.lock().unwrap().clone()
    }

    pub fn fail(&self, method: &str, failure: FixtureFailure) {
        self.state
            .failures
            .lock()
            .unwrap()
            .insert(method.to_owned(), failure);
    }

    pub fn clear_failures(&self) {
        self.state.failures.lock().unwrap().clear();
    }

    pub fn release_wait(&self) {
        self.state.wait.0.store(true, Ordering::SeqCst);
        self.state.wait.1.notify_waiters();
    }

    pub fn interactive(&self) -> bool {
        self.state.interactive.load(Ordering::SeqCst)
    }
}
