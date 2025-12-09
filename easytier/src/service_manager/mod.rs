use std::ffi::OsString;
use std::fmt::Write;
use std::path::PathBuf;

use service_manager::ServiceManager as _;

#[derive(Debug)]
pub struct ServiceInstallOptions {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub work_directory: PathBuf,
    pub disable_autostart: bool,
    pub description: Option<String>,
    pub display_name: Option<String>,
    pub disable_restart_on_failure: bool,
}

pub type ServiceStatus = service_manager::ServiceStatus;

trait ServiceManager: service_manager::ServiceManager {
    fn update(&self, ctx: service_manager::ServiceInstallCtx) -> std::io::Result<()>;
}
impl ServiceManager for service_manager::TypedServiceManager {
    fn update(&self, ctx: service_manager::ServiceInstallCtx) -> std::io::Result<()> {
        let status = self.status(service_manager::ServiceStatusCtx {
            label: ctx.label.clone(),
        })?;
        if status == ServiceStatus::Running {
            self.stop(service_manager::ServiceStopCtx {
                label: ctx.label.clone(),
            })?;
        }
        if status != ServiceStatus::NotInstalled {
            self.uninstall(service_manager::ServiceUninstallCtx {
                label: ctx.label.clone(),
            })?;
        }
        self.install(ctx)
    }
}

pub struct Service {
    label: service_manager::ServiceLabel,
    kind: service_manager::ServiceManagerKind,
    service_manager: Box<dyn ServiceManager>,
}

impl Service {
    pub fn new(name: String) -> Result<Self, anyhow::Error> {
        #[cfg(target_os = "windows")]
        let service_manager = Box::new(self::win_service_manager::WinServiceManager::new()?);
        #[cfg(target_os = "macos")]
        let service_manager: Box<dyn ServiceManager> =
            Box::new(service_manager::TypedServiceManager::Launchd(
                service_manager::LaunchdServiceManager::system().with_config(
                    service_manager::LaunchdConfig {
                        install: service_manager::LaunchdInstallConfig {
                            keep_alive: service_manager::KeepAlive::conditions()
                                .crashed(true)
                                .successful_exit(false),
                        },
                    },
                ),
            ));

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let service_manager: Box<dyn ServiceManager> =
            Box::new(service_manager::TypedServiceManager::native()?);

        let kind = service_manager::ServiceManagerKind::native()?;

        println!("service manager kind: {:?}", kind);

        Ok(Self {
            label: name.parse()?,
            kind,
            service_manager,
        })
    }

    pub fn install(&self, options: &ServiceInstallOptions) -> Result<(), anyhow::Error> {
        let ctx = service_manager::ServiceInstallCtx {
            label: self.label.clone(),
            program: options.program.clone(),
            args: options.args.clone(),
            contents: self.make_install_content_option(options),
            autostart: !options.disable_autostart,
            username: None,
            working_directory: Some(options.work_directory.clone()),
            environment: None,
            disable_restart_on_failure: options.disable_restart_on_failure,
        };

        if self.status()? != service_manager::ServiceStatus::NotInstalled {
            self.service_manager
                .update(ctx)
                .map_err(|e| anyhow::anyhow!("failed to update service: {:?}", e))?;
            println!("Service updated successfully! Service Name: {}", self.label);
            return Ok(());
        }

        self.service_manager
            .install(ctx)
            .map_err(|e| anyhow::anyhow!("failed to install service: {:?}", e))?;

        println!(
            "Service installed successfully! Service Name: {}",
            self.label
        );

        Ok(())
    }

    pub fn uninstall(&self) -> Result<(), anyhow::Error> {
        let ctx = service_manager::ServiceUninstallCtx {
            label: self.label.clone(),
        };
        let status = self.status()?;

        if status == service_manager::ServiceStatus::NotInstalled {
            return Err(anyhow::anyhow!("Service is not installed"))?;
        }

        if status == service_manager::ServiceStatus::Running {
            self.service_manager.stop(service_manager::ServiceStopCtx {
                label: self.label.clone(),
            })?;
        }

        self.service_manager
            .uninstall(ctx)
            .map_err(|e| anyhow::anyhow!("failed to uninstall service: {}", e))
    }

    pub fn status(&self) -> Result<service_manager::ServiceStatus, anyhow::Error> {
        let ctx = service_manager::ServiceStatusCtx {
            label: self.label.clone(),
        };
        let status = self.service_manager.status(ctx)?;

        Ok(status)
    }

    pub fn start(&self) -> Result<(), anyhow::Error> {
        let ctx = service_manager::ServiceStartCtx {
            label: self.label.clone(),
        };
        let status = self.status()?;

        match status {
            service_manager::ServiceStatus::Running => {
                Err(anyhow::anyhow!("Service is already running"))?
            }
            service_manager::ServiceStatus::Stopped(_) => {
                self.service_manager
                    .start(ctx)
                    .map_err(|e| anyhow::anyhow!("failed to start service: {}", e))?;
                Ok(())
            }
            service_manager::ServiceStatus::NotInstalled => {
                Err(anyhow::anyhow!("Service is not installed"))?
            }
        }
    }

    pub fn stop(&self) -> Result<(), anyhow::Error> {
        let ctx = service_manager::ServiceStopCtx {
            label: self.label.clone(),
        };
        let status = self.status()?;

        match status {
            service_manager::ServiceStatus::Running => {
                self.service_manager
                    .stop(ctx)
                    .map_err(|e| anyhow::anyhow!("failed to stop service: {}", e))?;
                Ok(())
            }
            service_manager::ServiceStatus::Stopped(_) => {
                Err(anyhow::anyhow!("Service is already stopped"))?
            }
            service_manager::ServiceStatus::NotInstalled => {
                Err(anyhow::anyhow!("Service is not installed"))?
            }
        }
    }

    fn make_install_content_option(&self, options: &ServiceInstallOptions) -> Option<String> {
        match self.kind {
            service_manager::ServiceManagerKind::Systemd => {
                Some(self.make_systemd_unit(options).unwrap())
            }
            service_manager::ServiceManagerKind::Rcd => {
                Some(self.make_rcd_script(options).unwrap())
            }
            service_manager::ServiceManagerKind::OpenRc => {
                Some(self.make_open_rc_script(options).unwrap())
            }
            service_manager::ServiceManagerKind::Launchd => {
                None // 使用 service-manager-rs 的默认 plist 生成
            }
            _ => {
                #[cfg(target_os = "windows")]
                {
                    let win_options = self::win_service_manager::WinServiceInstallOptions {
                        description: options.description.clone(),
                        display_name: options.display_name.clone(),
                        dependencies: Some(vec!["rpcss".to_string(), "dnscache".to_string()]),
                    };

                    Some(serde_json::to_string(&win_options).unwrap())
                }

                #[cfg(not(target_os = "windows"))]
                None
            }
        }
    }

    fn make_systemd_unit(
        &self,
        options: &ServiceInstallOptions,
    ) -> Result<String, std::fmt::Error> {
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut unit_content = String::new();

        writeln!(unit_content, "[Unit]")?;
        writeln!(unit_content, "After=network.target syslog.target")?;
        if let Some(ref d) = options.description {
            writeln!(unit_content, "Description={d}")?;
        }
        writeln!(unit_content, "StartLimitIntervalSec=0")?;
        writeln!(unit_content)?;
        writeln!(unit_content, "[Service]")?;
        writeln!(unit_content, "Type=simple")?;
        writeln!(unit_content, "WorkingDirectory={work_dir}")?;
        writeln!(unit_content, "ExecStart={target_app} {args}")?;
        writeln!(unit_content, "Restart=always")?;
        writeln!(unit_content, "RestartSec=1")?;
        writeln!(unit_content, "LimitNOFILE=infinity")?;
        writeln!(unit_content)?;
        writeln!(unit_content, "[Install]")?;
        writeln!(unit_content, "WantedBy=multi-user.target")?;

        std::result::Result::Ok(unit_content)
    }

    fn make_rcd_script(&self, options: &ServiceInstallOptions) -> Result<String, std::fmt::Error> {
        let name = self.label.to_qualified_name();
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut script = String::new();

        writeln!(script, "#!/bin/sh")?;
        writeln!(script, "#")?;
        writeln!(script, "# PROVIDE: {name}")?;
        writeln!(script, "# REQUIRE: LOGIN FILESYSTEMS NETWORKING ")?;
        writeln!(script, "# KEYWORD: shutdown")?;
        writeln!(script)?;
        writeln!(script, ". /etc/rc.subr")?;
        writeln!(script)?;
        writeln!(script, "name=\"{name}\"")?;
        if let Some(ref d) = options.description {
            writeln!(script, "desc=\"{d}\"")?;
        }
        writeln!(script, "rcvar=\"{name}_enable\"")?;
        writeln!(script)?;
        writeln!(script, "load_rc_config ${{name}}")?;
        writeln!(script)?;
        writeln!(script, ": ${{{name}_options=\"{args}\"}}")?;
        writeln!(script)?;
        writeln!(script, "{name}_chdir=\"{work_dir}\"")?;
        writeln!(script, "pidfile=\"/var/run/${{name}}.pid\"")?;
        writeln!(script, "procname=\"{target_app}\"")?;
        writeln!(script, "command=\"/usr/sbin/daemon\"")?;
        writeln!(
            script,
            "command_args=\"-c -S -T ${{name}} -p ${{pidfile}} ${{procname}} ${{{name}_options}}\""
        )?;
        writeln!(script)?;
        writeln!(script, "run_rc_command \"$1\"")?;

        std::result::Result::Ok(script)
    }

    fn make_open_rc_script(
        &self,
        options: &ServiceInstallOptions,
    ) -> Result<String, std::fmt::Error> {
        let args = options
            .args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let target_app = options.program.display().to_string();
        let work_dir = options.work_directory.display().to_string();
        let mut script = String::new();

        writeln!(script, "#!/sbin/openrc-run")?;
        writeln!(script)?;
        if let Some(ref d) = options.description {
            writeln!(script, "description=\"{d}\"")?;
        }
        writeln!(script, "command=\"{target_app}\"")?;
        writeln!(script, "command_args=\"{args}\"")?;
        writeln!(script, "pidfile=\"/run/${{RC_SVCNAME}}.pid\"")?;
        writeln!(script, "command_background=\"yes\"")?;
        writeln!(script, "directory=\"{work_dir}\"")?;
        writeln!(script)?;
        writeln!(script, "depend() {{")?;
        writeln!(script, "    need net")?;
        writeln!(script, "    use looger")?;
        writeln!(script, "}}")?;

        std::result::Result::Ok(script)
    }
}

#[cfg(target_os = "windows")]
mod win_service_manager {
    use std::{ffi::OsStr, ffi::OsString, io, path::PathBuf};
    use windows_service::{
        service::{
            ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    use service_manager::{
        ServiceInstallCtx, ServiceLevel, ServiceStartCtx, ServiceStatus, ServiceStatusCtx,
        ServiceStopCtx, ServiceUninstallCtx,
    };

    use winreg::{enums::*, RegKey};

    use crate::common::constants::WIN_SERVICE_WORK_DIR_REG_KEY;

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct WinServiceInstallOptions {
        pub dependencies: Option<Vec<String>>,
        pub description: Option<String>,
        pub display_name: Option<String>,
    }

    pub struct WinServiceManager {
        service_manager: ServiceManager,
    }

    fn generate_service_info(ctx: &ServiceInstallCtx) -> (ServiceInfo, Option<OsString>) {
        let start_type = if ctx.autostart {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::OnDemand
        };
        let srv_name = OsString::from(ctx.label.to_qualified_name());
        let mut dis_name = srv_name.clone();
        let mut description: Option<OsString> = None;
        let mut dependencies = Vec::<ServiceDependency>::new();

        if let Some(s) = ctx.contents.as_ref() {
            let options: WinServiceInstallOptions = serde_json::from_str(s.as_str()).unwrap();
            if let Some(d) = options.dependencies {
                dependencies = d
                    .iter()
                    .map(|dep| ServiceDependency::Service(OsString::from(dep.clone())))
                    .collect::<Vec<_>>();
            }
            if let Some(d) = options.description {
                description = Some(OsString::from(d));
            }
            if let Some(d) = options.display_name {
                dis_name = OsString::from(d);
            }
        }

        let service_info = ServiceInfo {
            name: srv_name,
            display_name: dis_name,
            service_type: ServiceType::OWN_PROCESS,
            start_type,
            error_control: ServiceErrorControl::Normal,
            executable_path: ctx.program.clone(),
            launch_arguments: ctx.args.clone(),
            dependencies: dependencies.clone(),
            account_name: None,
            account_password: None,
        };

        (service_info, description)
    }

    impl WinServiceManager {
        pub fn new() -> Result<Self, anyhow::Error> {
            let service_manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::ALL_ACCESS)?;
            Ok(Self { service_manager })
        }
    }
    impl service_manager::ServiceManager for WinServiceManager {
        fn available(&self) -> io::Result<bool> {
            Ok(true)
        }

        fn install(&self, ctx: ServiceInstallCtx) -> io::Result<()> {
            let (service_info, description) = generate_service_info(&ctx);

            let service = self
                .service_manager
                .create_service(&service_info, ServiceAccess::ALL_ACCESS)
                .map_err(io::Error::other)?;

            if let Some(s) = description {
                service
                    .set_description(s.clone())
                    .map_err(io::Error::other)?;
            }

            if let Some(work_dir) = ctx.working_directory {
                set_service_work_directory(&ctx.label.to_qualified_name(), work_dir)?;
            }

            Ok(())
        }

        fn uninstall(&self, ctx: ServiceUninstallCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(io::Error::other)?;

            service.delete().map_err(io::Error::other)
        }

        fn start(&self, ctx: ServiceStartCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(io::Error::other)?;

            service.start(&[] as &[&OsStr]).map_err(io::Error::other)
        }

        fn stop(&self, ctx: ServiceStopCtx) -> io::Result<()> {
            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(io::Error::other)?;

            _ = service.stop().map_err(io::Error::other)?;

            Ok(())
        }

        fn level(&self) -> ServiceLevel {
            ServiceLevel::System
        }

        fn set_level(&mut self, level: ServiceLevel) -> io::Result<()> {
            match level {
                ServiceLevel::System => Ok(()),
                _ => Err(io::Error::other("Unsupported service level")),
            }
        }

        fn status(&self, ctx: ServiceStatusCtx) -> io::Result<ServiceStatus> {
            let service = match self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::QUERY_STATUS)
            {
                Ok(s) => s,
                Err(e) => {
                    if let windows_service::Error::Winapi(ref win_err) = e {
                        if win_err.raw_os_error() == Some(0x424) {
                            return Ok(ServiceStatus::NotInstalled);
                        }
                    }
                    return Err(io::Error::other(e));
                }
            };

            let status = service.query_status().map_err(io::Error::other)?;

            match status.current_state {
                windows_service::service::ServiceState::Stopped => Ok(ServiceStatus::Stopped(None)),
                _ => Ok(ServiceStatus::Running),
            }
        }
    }

    impl super::ServiceManager for WinServiceManager {
        fn update(&self, ctx: service_manager::ServiceInstallCtx) -> io::Result<()> {
            let (service_info, description) = generate_service_info(&ctx);

            let service = self
                .service_manager
                .open_service(ctx.label.to_qualified_name(), ServiceAccess::ALL_ACCESS)
                .map_err(io::Error::other)?;

            service
                .change_config(&service_info)
                .map_err(io::Error::other)?;

            if let Some(s) = description {
                service
                    .set_description(s.clone())
                    .map_err(io::Error::other)?;
            }

            if let Some(work_dir) = ctx.working_directory {
                set_service_work_directory(&ctx.label.to_qualified_name(), work_dir)?;
            }

            Ok(())
        }
    }

    fn set_service_work_directory(service_name: &str, work_directory: PathBuf) -> io::Result<()> {
        let (reg_key, _) =
            RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(WIN_SERVICE_WORK_DIR_REG_KEY)?;
        reg_key
            .set_value::<OsString, _>(service_name, &work_directory.as_os_str().to_os_string())?;
        Ok(())
    }
}
