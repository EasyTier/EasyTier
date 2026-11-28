//! A private bus carrying the parts of the NetworkManager API the configurator
//! uses: the manager's device list, the DNS manager's mode, and one device that
//! implements `GetAppliedConnection` / `Reapply` with the same semantics
//! (including rejecting a stale version id).

use std::{
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use zbus::{
    blocking::{Connection, connection::Builder},
    fdo,
    zvariant::OwnedObjectPath,
};

use super::{NetworkManagerConfigurator, Settings, manages_dns};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const DNS_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/DnsManager";
const DEVICE_PATH: &str = "/org/freedesktop/NetworkManager/Devices/1";

#[derive(Default)]
pub struct FixtureState {
    pub mode: Mutex<String>,
    pub settings: Mutex<Settings>,
    pub version: Mutex<u64>,
    pub reapplied: Mutex<Vec<Settings>>,
}

struct ManagerObject {
    state: Arc<FixtureState>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl ManagerObject {
    #[zbus(property)]
    fn devices(&self) -> Vec<OwnedObjectPath> {
        let _ = &self.state;
        vec![OwnedObjectPath::try_from(DEVICE_PATH).unwrap()]
    }
}

struct DnsManagerObject {
    state: Arc<FixtureState>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.DnsManager")]
impl DnsManagerObject {
    #[zbus(property)]
    fn mode(&self) -> String {
        self.state.mode.lock().unwrap().clone()
    }
}

struct DeviceObject {
    state: Arc<FixtureState>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl DeviceObject {
    fn get_applied_connection(&self, _flags: u32) -> fdo::Result<(Settings, u64)> {
        Ok((
            self.state.settings.lock().unwrap().clone(),
            *self.state.version.lock().unwrap(),
        ))
    }

    fn reapply(&self, settings: Settings, version: u64, _flags: u32) -> fdo::Result<()> {
        if version != *self.state.version.lock().unwrap() {
            return Err(fdo::Error::Failed(
                "stale applied connection version".to_owned(),
            ));
        }
        *self.state.settings.lock().unwrap() = settings.clone();
        self.state.reapplied.lock().unwrap().push(settings);
        Ok(())
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
            .stderr(Stdio::null())
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct NetworkManagerFixture {
    pub address: String,
    state: Arc<FixtureState>,
    _server: Connection,
    _daemon: BusDaemon,
}

impl NetworkManagerFixture {
    pub fn start(mode: &str, settings: Settings) -> Self {
        let (daemon, address) = BusDaemon::start();
        let state = Arc::new(FixtureState {
            mode: Mutex::new(mode.to_owned()),
            settings: Mutex::new(settings),
            version: Mutex::new(1),
            ..Default::default()
        });
        let server = Builder::address(address.as_str())
            .unwrap()
            .name(SERVICE)
            .unwrap()
            .serve_at(
                MANAGER_PATH,
                ManagerObject {
                    state: state.clone(),
                },
            )
            .unwrap()
            .serve_at(
                DNS_MANAGER_PATH,
                DnsManagerObject {
                    state: state.clone(),
                },
            )
            .unwrap()
            .serve_at(
                DEVICE_PATH,
                DeviceObject {
                    state: state.clone(),
                },
            )
            .unwrap()
            .build()
            .unwrap();
        Self {
            address,
            state,
            _server: server,
            _daemon: daemon,
        }
    }

    pub fn connection(&self) -> Connection {
        Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .unwrap()
    }

    pub fn configurator(&self) -> NetworkManagerConfigurator {
        NetworkManagerConfigurator::with_connection(self.connection())
    }

    pub fn settings(&self) -> Settings {
        self.state.settings.lock().unwrap().clone()
    }

    /// Simulate a reactivation: the device falls back to its profile and the
    /// version id moves on, which is exactly what invalidates a stored one.
    pub fn revert_to(&self, settings: Settings) {
        *self.state.settings.lock().unwrap() = settings;
        *self.state.version.lock().unwrap() += 1;
    }

    pub fn reapply_count(&self) -> usize {
        self.state.reapplied.lock().unwrap().len()
    }

    pub fn manages_dns(&self) -> bool {
        manages_dns(&self.connection()).unwrap()
    }
}
