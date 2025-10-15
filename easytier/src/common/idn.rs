use idna::domain_to_ascii;
pub fn convert_idn_to_ascii(url_str: &str) -> Result<String, String> {
    if !url_str.is_ascii() {
        let mut url_parts = url_str.splitn(2, "://");
        let scheme = url_parts.next().unwrap_or("");
        let rest = url_parts.next().unwrap_or(url_str);
        let (host_part, port_part, path_part) = {
            let mut path_and_rest = rest.splitn(2, '/');
            let host_port_part = path_and_rest.next().unwrap_or("");
            let path_part = path_and_rest
                .next()
                .map(|s| format!("/{}", s))
                .unwrap_or_default();
            if host_port_part.starts_with('[') {
                if let Some(end_bracket_pos) = host_port_part.find(']') {
                    let host_part = &host_port_part[..end_bracket_pos + 1];
                    let remaining = &host_port_part[end_bracket_pos + 1..];
                    if remaining.starts_with(':') {
                        if let Some(port_str) = remaining.strip_prefix(':') {
                            if port_str.chars().all(|c| c.is_ascii_digit()) {
                                (host_part, format!(":{}", port_str), path_part)
                            } else {
                                (host_part, String::new(), path_part)
                            }
                        } else {
                            (host_part, String::new(), path_part)
                        }
                    } else {
                        (host_part, String::new(), path_part)
                    }
                } else {
                    (host_port_part, String::new(), path_part)
                }
            } else {
                let (host_part, port_part) = if let Some(pos) = host_port_part.rfind(':') {
                    let port_str = &host_port_part[pos + 1..];
                    if port_str.chars().all(|c| c.is_ascii_digit()) {
                        (&host_port_part[..pos], format!(":{}", port_str))
                    } else {
                        (host_port_part, String::new())
                    }
                } else {
                    (host_port_part, String::new())
                };
                (host_part, port_part, path_part)
            }
        };

        if !host_part.is_ascii() {
            let ascii_host = domain_to_ascii(host_part)
                .map_err(|e| format!("Failed to convert IDN to ASCII: {}", e))?;
            let result = format!("{}://{}{}{}", scheme, ascii_host, port_part, path_part);
            Ok(result)
        } else {
            Ok(url_str.to_string())
        }
    } else {
        Ok(url_str.to_string())
    }
}
pub fn safe_convert_idn_to_ascii(url_str: &str) -> String {
    convert_idn_to_ascii(url_str).unwrap_or_else(|_| url_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_only_urls() {
        assert_eq!(
            convert_idn_to_ascii("https://example.com").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            convert_idn_to_ascii("http://test.org:8080/path").unwrap(),
            "http://test.org:8080/path"
        );
    }

    #[test]
    fn test_unicode_domains() {
        assert_eq!(
            convert_idn_to_ascii("https://räksmörgås.nu").unwrap(),
            "https://xn--rksmrgs-5wao1o.nu"
        );
        assert_eq!(
            convert_idn_to_ascii("https://例子.测试").unwrap(),
            "https://xn--fsqu00a.xn--0zwm56d"
        );
    }

    #[test]
    fn test_chinese_domains() {
        assert_eq!(
            convert_idn_to_ascii("https://中文.测试").unwrap(),
            "https://xn--fiq228c.xn--0zwm56d"
        );
        assert_eq!(
            convert_idn_to_ascii("https://公司.中国").unwrap(),
            "https://xn--55qx5d.xn--fiqs8s"
        );
        assert_eq!(
            convert_idn_to_ascii("https://网络.测试").unwrap(),
            "https://xn--io0a7i.xn--0zwm56d"
        );
    }

    #[test]
    fn test_unicode_domains_with_port() {
        assert_eq!(
            convert_idn_to_ascii("https://räksmörgås.nu:8080").unwrap(),
            "https://xn--rksmrgs-5wao1o.nu:8080"
        );
        assert_eq!(
            convert_idn_to_ascii("http://例子.测试:3000/path").unwrap(),
            "http://xn--fsqu00a.xn--0zwm56d:3000/path"
        );
        assert_eq!(
            convert_idn_to_ascii("https://中文.测试:9000/api").unwrap(),
            "https://xn--fiq228c.xn--0zwm56d:9000/api"
        );
    }

    #[test]
    fn test_unicode_domains_with_path() {
        assert_eq!(
            convert_idn_to_ascii("https://räksmörgås.nu/path/to/resource").unwrap(),
            "https://xn--rksmrgs-5wao1o.nu/path/to/resource"
        );
        assert_eq!(
            convert_idn_to_ascii("http://例子.测试/api/v1").unwrap(),
            "http://xn--fsqu00a.xn--0zwm56d/api/v1"
        );
        assert_eq!(
            convert_idn_to_ascii("https://中文.测试/api/users").unwrap(),
            "https://xn--fiq228c.xn--0zwm56d/api/users"
        );
    }

    #[test]
    fn test_unicode_domains_with_port_and_path() {
        assert_eq!(
            convert_idn_to_ascii("https://räksmörgås.nu:8080/path/to/resource").unwrap(),
            "https://xn--rksmrgs-5wao1o.nu:8080/path/to/resource"
        );
        assert_eq!(
            convert_idn_to_ascii("http://例子.测试:9000/api/v1/users").unwrap(),
            "http://xn--fsqu00a.xn--0zwm56d:9000/api/v1/users"
        );
        assert_eq!(
            convert_idn_to_ascii("https://中文.测试:8000/用户/管理").unwrap(),
            "https://xn--fiq228c.xn--0zwm56d:8000/用户/管理"
        );
    }

    #[test]
    fn test_ipv6_literals() {
        assert_eq!(
            convert_idn_to_ascii("https://[2001:db8::1]:8080").unwrap(),
            "https://[2001:db8::1]:8080"
        );
        assert_eq!(
            convert_idn_to_ascii("https://[2001:db8::1]/path").unwrap(),
            "https://[2001:db8::1]/path"
        );
        assert_eq!(
            convert_idn_to_ascii("https://[2001:db8::1]/路径/资源").unwrap(),
            "https://[2001:db8::1]/路径/资源"
        );
    }

    #[test]
    fn test_invalid_port_format() {
        let result = convert_idn_to_ascii("https://räksmörgås.nu:notaport").unwrap();
        assert!(result.contains("xn--") && result.contains(":notaport"));
    }

    #[test]
    fn test_safe_conversion() {
        assert_eq!(
            safe_convert_idn_to_ascii("https://example.com"),
            "https://example.com"
        );
        assert_eq!(
            safe_convert_idn_to_ascii("https://中文.测试"),
            "https://xn--fiq228c.xn--0zwm56d"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Without scheme '://', entire string is treated as host part
        let result = convert_idn_to_ascii("räksmörgås.nu").unwrap();
        assert_eq!(result, "räksmörgås.nu://xn--rksmrgs-5wao1o.nu");

        assert_eq!(
            convert_idn_to_ascii("https://test.例子.com").unwrap(),
            "https://test.xn--fsqu00a.com"
        );
    }

    #[test]
    fn test_ipv6_with_unicode_path() {
        assert_eq!(
            convert_idn_to_ascii("https://[2001:db8::1]/路径/资源").unwrap(),
            "https://[2001:db8::1]/路径/资源"
        );
    }
}
