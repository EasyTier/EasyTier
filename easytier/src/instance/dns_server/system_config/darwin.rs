use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use super::{OSConfig, SystemConfig};

const MAC_RESOLVER_FILE_HEADER: &str = "# Added by easytier\n";
const ETC_RESOLVER: &str = "/etc/resolver";
const ETC_RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct DarwinConfigurator {}

impl DarwinConfigurator {
    pub fn new() -> Self {
        DarwinConfigurator {}
    }

    pub fn do_close(&self) -> io::Result<()> {
        self.remove_resolver_files(|_| true)
    }

    pub fn supports_split_dns(&self) -> bool {
        true
    }

    pub fn do_set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        fs::create_dir_all(ETC_RESOLVER)?;
        let mut keep = HashSet::new();

        // 写 search.easytier 文件
        if !cfg.search_domains.is_empty() {
            let search_file = "search.easytier";
            keep.insert(search_file.to_string());
            let mut content = String::from(MAC_RESOLVER_FILE_HEADER);
            content.push_str("search");
            for domain in &cfg.search_domains {
                content.push(' ');
                content.push_str(domain.trim_end_matches('.'));
            }
            content.push('\n');
            Self::write_resolver_file(search_file, &content)?;
        }

        // 写 match_domains 文件
        let mut ns_content = String::from(MAC_RESOLVER_FILE_HEADER);
        for ns in &cfg.nameservers {
            ns_content.push_str(&format!("nameserver {}\n", ns));
        }
        for domain in &cfg.match_domains {
            let file_base = domain.trim_end_matches('.');
            keep.insert(file_base.to_string());
            Self::write_resolver_file(file_base, &ns_content)?;
        }
        // 删除未保留的 resolver 文件
        self.remove_resolver_files(|domain| !keep.contains(domain))?;

        Ok(())
    }

    fn write_resolver_file(file_name: &str, content: &str) -> io::Result<()> {
        let path = Path::new(ETC_RESOLVER).join(file_name);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    fn remove_resolver_files<F>(&self, should_delete: F) -> io::Result<()>
    where
        F: Fn(&str) -> bool,
    {
        let entries = match fs::read_dir(ETC_RESOLVER) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !should_delete(&name_str) {
                continue;
            }
            let full_path = entry.path();
            let content = fs::read_to_string(&full_path)?;
            if !content.starts_with(MAC_RESOLVER_FILE_HEADER) {
                continue;
            }
            fs::remove_file(&full_path)?;
        }
        Ok(())
    }
}

impl SystemConfig for DarwinConfigurator {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        self.do_set_dns(cfg)
    }

    fn close(&self) -> io::Result<()> {
        self.do_close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_dns_test() -> io::Result<()> {
        let config = OSConfig {
            nameservers: vec!["8.8.8.8".into()],
            search_domains: vec!["example.com".into()],
            match_domains: vec!["test.local".into()],
        };
        let configurator = DarwinConfigurator::new();

        configurator.set_dns(&config)?;
        configurator.close()?;

        Ok(())
    }
}
