use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

mod hosts;
mod nrpt; // NRPT 操作模块
mod registry; // 自定义注册表访问模块
mod wsl; // WSL 支持模块 // Hosts 文件操作模块

pub struct WindowsDNSManager {
    log: Box<dyn Fn(&str)>,
    interface_guid: String,
    closing: bool,
    nrpt_db: Option<nrpt::NRPTDatabase>,
    wsl_manager: Option<wsl::WSLManager>,
}

impl WindowsDNSManager {
    pub fn new(interface_guid: String) -> Self {
        Self {
            log: Box::new(|msg| println!("{}", msg)),
            interface_guid,
            closing: false,
            nrpt_db: if is_windows_10_or_better() {
                Some(nrpt::NRPTDatabase::new())
            } else {
                None
            },
            wsl_manager: Some(wsl::WSLManager::new()),
        }
    }

    fn set_primary_dns(&self, resolvers: Vec<&str>, domains: Vec<&str>) -> Result<(), String> {
        // 设置主 DNS（修改注册表）
        registry::set_primary_resolver(&self.interface_guid, resolvers)?;
        registry::set_search_domains(&self.interface_guid, domains)?;
        Ok(())
    }

    fn set_split_dns(&self, resolvers: Vec<&str>, domains: Vec<&str>) -> Result<(), String> {
        if let Some(ref db) = self.nrpt_db {
            db.write_split_dns_config(resolvers, domains)
        } else {
            Err("Split DNS not supported on this Windows version".into())
        }
    }

    fn set_hosts(&self, hosts: &[HostEntry]) -> Result<(), String> {
        hosts::update_hosts_file(hosts)
    }

    pub fn set_dns(&mut self, config: DNSConfig) -> Result<(), String> {
        // 清理旧配置
        self.disable_dynamic_updates()?;
        self.disable_netbios()?;

        if config.match_domains.is_empty() {
            self.set_primary_dns(config.nameservers, config.search_domains)?;
        } else {
            self.set_split_dns(config.nameservers, config.match_domains)?;
            self.set_primary_dns(vec![], config.search_domains)?;
            self.set_hosts(&config.hosts)?;
        }

        // 刷新 DNS 缓存
        Command::new("ipconfig").arg("/flushdns").spawn()?.wait()?;

        // 启动 WSL 设置（可选）
        if let Some(ref mut wsl_mgr) = self.wsl_manager {
            wsl_mgr.set_dns(config)?;
        }

        Ok(())
    }

    fn disable_dynamic_updates(&self) -> Result<(), String> {
        registry::disable_dynamic_update(&self.interface_guid)
    }

    fn disable_netbios(&self) -> Result<(), String> {
        registry::disable_netbios(&self.interface_guid)
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.closing = true;
        self.set_dns(DNSConfig::default())
    }
}

#[derive(Default)]
pub struct DNSConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub match_domains: Vec<String>,
    pub hosts: Vec<HostEntry>,
}

pub struct HostEntry {
    pub ip: String,
    pub names: Vec<String>,
}
