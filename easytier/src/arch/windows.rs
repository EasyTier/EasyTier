use std::{
    ffi::{c_void, OsStr, OsString},
    io::{self, ErrorKind},
    mem,
    net::SocketAddr,
    os::windows::io::AsRawSocket,
    ptr,
};

use network_interface::NetworkInterfaceConfig;
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, FALSE, ERROR_SERVICE_DOES_NOT_EXIST},
        Networking::WinSock::{
            htonl, setsockopt, WSAGetLastError, WSAIoctl, IPPROTO_IP, IPPROTO_IPV6,
            IPV6_UNICAST_IF, IP_UNICAST_IF, SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR,
        },
    },
};
use service_manager::{
    ServiceInstallCtx, 
    ServiceLevel, 
    ServiceStartCtx, 
    ServiceStatus, 
    ServiceStatusCtx, 
    ServiceUninstallCtx,
    ServiceStopCtx
};
use windows_service::service::{
    ServiceType,
    ServiceErrorControl,
    ServiceDependency,
    ServiceInfo,
    ServiceStartType,
    ServiceAccess
};
use windows_service::service_manager::{
    ServiceManagerAccess,
    ServiceManager
};

pub fn disable_connection_reset<S: AsRawSocket>(socket: &S) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    unsafe {
        // Ignoring UdpSocket's WSAECONNRESET error
        // https://github.com/shadowsocks/shadowsocks-rust/issues/179
        // https://stackoverflow.com/questions/30749423/is-winsock-error-10054-wsaeconnreset-normal-with-udp-to-from-localhost
        //
        // This is because `UdpSocket::recv_from` may return WSAECONNRESET
        // if you called `UdpSocket::send_to` a destination that is not existed (may be closed).
        //
        // It is not an error. Could be ignored completely.
        // We have to ignore it here because it will crash the server.

        let mut bytes_returned: u32 = 0;
        let enable: BOOL = FALSE;

        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            &enable as *const _ as *const c_void,
            mem::size_of_val(&enable) as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned as *mut _,
            ptr::null_mut(),
            None,
        );

        if ret == SOCKET_ERROR {
            use std::io::Error;

            // Error occurs
            let err_code = WSAGetLastError();
            return Err(Error::from_raw_os_error(err_code));
        }
    }

    Ok(())
}

pub fn interface_count() -> io::Result<usize> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            ErrorKind::NotFound,
            format!("Failed to get interfaces. error: {}", e),
        )
    })?;
    Ok(ifaces.len())
}

pub fn find_interface_index(iface_name: &str) -> io::Result<u32> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            ErrorKind::NotFound,
            format!("Failed to get interfaces. {}, error: {}", iface_name, e),
        )
    })?;
    if let Some(iface) = ifaces.iter().find(|iface| iface.name == iface_name) {
        return Ok(iface.index);
    }
    tracing::error!("Failed to find interface index for {}", iface_name);
    Err(io::Error::new(
        ErrorKind::NotFound,
        format!("{}", iface_name),
    ))
}

pub fn set_ip_unicast_if<S: AsRawSocket>(
    socket: &S,
    addr: &SocketAddr,
    iface: &str,
) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    let if_index = find_interface_index(iface)?;

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => {
                // Interface index is in network byte order for IPPROTO_IP.
                let if_index = htonl(if_index);
                setsockopt(
                    handle,
                    IPPROTO_IP as i32,
                    IP_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
            SocketAddr::V6(..) => {
                // Interface index is in host byte order for IPPROTO_IPV6.
                setsockopt(
                    handle,
                    IPPROTO_IPV6 as i32,
                    IPV6_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
        };

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            tracing::error!(
                "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                iface,
                if_index,
                err
            );
            return Err(err);
        }
    }

    Ok(())
}

pub fn setup_socket_for_win<S: AsRawSocket>(
    socket: &S,
    bind_addr: &SocketAddr,
    bind_dev: Option<String>,
    is_udp: bool,
) -> io::Result<()> {
    if is_udp {
        disable_connection_reset(socket)?;
    }

    if let Some(iface) = bind_dev {
        set_ip_unicast_if(socket, bind_addr, iface.as_str())?;
    }

    Ok(())
}

pub struct WinServiceManager {
    service_manager: ServiceManager,
    display_name: Option<OsString>,
    description: Option<OsString>,
    dependencies: Vec<OsString>  
}

impl WinServiceManager {
    pub fn new(display_name: Option<OsString>, description: Option<OsString>, dependencies: Vec<OsString>,) -> Result<Self, windows_service::Error> {
        let service_manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::ALL_ACCESS,
        )?;
        Ok(Self {
            service_manager,
            display_name,
            description,
            dependencies,
        })
    }
}

impl service_manager::ServiceManager for WinServiceManager {
    fn available(&self) -> io::Result<bool> {
        Ok(true)
    }

    fn install(&self, ctx: ServiceInstallCtx) -> io::Result<()> {
        let start_type_ = if ctx.autostart { ServiceStartType::AutoStart } else { ServiceStartType::OnDemand };
        let srv_name = OsString::from(ctx.label.to_qualified_name());
        let dis_name = self.display_name.clone().unwrap_or_else(|| srv_name.clone());
        let dependencies = self.dependencies.iter().map(|dep| ServiceDependency::Service(dep.clone())).collect::<Vec<_>>();
        let service_info = ServiceInfo {
            name: srv_name,
            display_name: dis_name,
            service_type: ServiceType::OWN_PROCESS,
            start_type: start_type_,
            error_control: ServiceErrorControl::Normal,
            executable_path: ctx.program,
            launch_arguments: ctx.args,
            dependencies: dependencies.clone(),
            account_name: None,
            account_password: None
        };

        let service = self.service_manager.create_service(&service_info, ServiceAccess::ALL_ACCESS).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        if let Some(s) = &self.description {
            service.set_description(s.clone()).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e)
            })?;
        }

        Ok(())
    }
    
    fn uninstall(&self, ctx: ServiceUninstallCtx) -> io::Result<()> {
        let service = self.service_manager.open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS).map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        service.delete().map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })
    }
    
    fn start(&self, ctx: ServiceStartCtx) -> io::Result<()> {
        let service = self.service_manager.open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS).map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        service.start(&[] as &[&OsStr]).map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })
    }
    
    fn stop(&self, ctx: ServiceStopCtx) -> io::Result<()> {
        let service = self.service_manager.open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS).map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        _ = service.stop().map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        Ok(())
    }
    
    fn level(&self) -> ServiceLevel {
        ServiceLevel::System
    }
    
    fn set_level(&mut self, level: ServiceLevel) -> io::Result<()> {
        match level {
            ServiceLevel::System => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "Unsupported service level"))            
        }
    }
    
    fn status(&self, ctx: ServiceStatusCtx) -> io::Result<ServiceStatus> {
        let service = match self.service_manager.open_service(ctx.label.to_qualified_name(), ServiceAccess::QUERY_STATUS) {
            Ok(s) => s,
            Err(e) => {
                if let windows_service::Error::Winapi(ref win_err) = e {
                    if win_err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                        return Ok(ServiceStatus::NotInstalled);
                    }
                }
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };

        let status = service.query_status().map_err(|e|{
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        match status.current_state {
            windows_service::service::ServiceState::Stopped => Ok(ServiceStatus::Stopped(None)),
            _ => Ok(ServiceStatus::Running),
        }
    }
}

