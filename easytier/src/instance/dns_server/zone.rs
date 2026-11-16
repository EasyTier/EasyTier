pub(crate) use easytier_core::gateway::magic_dns::{dns_domain, parse_origin};

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::config::toml::TomlConfigLoader;
    #[test]
    fn dns_domain_prefers_dns_domain_and_falls_back_to_legacy_flag() {
        let loader = TomlConfigLoader::new_from_str("").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "et.net.");

        let loader = TomlConfigLoader::new_from_str("[dns]\ndomain = 'MESH.Example'\n").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "mesh.example.");

        let loader =
            TomlConfigLoader::new_from_str("[flags]\ntld_dns_zone = 'LEGACY.Example'\n").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "legacy.example.");

        let loader = TomlConfigLoader::new_from_str(
            "[dns]\ndomain = 'mesh.example'\n[flags]\ntld_dns_zone = 'legacy.example'\n",
        )
        .unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "mesh.example.");

        assert!(
            TomlConfigLoader::new_from_str(
                "[dns]\ndomain = ''\n[flags]\ntld_dns_zone = 'legacy.example'\n",
            )
            .is_err()
        );

        assert!(
            TomlConfigLoader::new_from_str(
                "[dns]\ndomain = '.'\n[flags]\ntld_dns_zone = 'legacy.example'\n",
            )
            .is_err()
        );

        let loader = TomlConfigLoader::new_from_str("[flags]\ntld_dns_zone = '.'\n").unwrap();
        assert!(dns_domain(&loader).is_err());
    }
}
