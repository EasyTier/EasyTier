use idna::domain_to_ascii;
use percent_encoding::percent_decode_str;

pub fn convert_idn_to_ascii(mut url: url::Url) -> anyhow::Result<url::Url> {
    if url.is_special() {
        return Ok(url);
    }
    if let Some(domain) = url.domain() {
        let domain = percent_decode_str(domain).decode_utf8()?;
        let domain = domain_to_ascii(&domain)?;
        url.set_host(Some(&domain))?;
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // test_ascii_only_urls
    #[case("example.com", "example.com")]
    #[case("test.org:8080/path", "test.org:8080/path")]
    // test_unicode_domains
    #[case("räksmörgås.nu", "xn--rksmrgs-5wao1o.nu")]
    #[case("中文.测试", "xn--fiq228c.xn--0zwm56d")]
    // test_unicode_domains_with_port
    #[case("räksmörgås.nu:8080", "xn--rksmrgs-5wao1o.nu:8080")]
    // test_unicode_domains_with_port_and_path
    #[case("例子.测试/path", "xn--fsqu00a.xn--0zwm56d/path")]
    #[case("中文.测试:9000/api", "xn--fiq228c.xn--0zwm56d:9000/api")]
    #[case("räksmörgås.nu:8080/path", "xn--rksmrgs-5wao1o.nu:8080/path")]
    // test_unicode_domains_with_port_and_unicode_path
    #[case(
        "中文.测试:8000/用户/管理",
        "xn--fiq228c.xn--0zwm56d:8000/%E7%94%A8%E6%88%B7/%E7%AE%A1%E7%90%86"
    )]
    // test_ipv6_literals & test_ipv6_with_unicode_path
    #[case("[2001:db8::1]:8080", "[2001:db8::1]:8080")]
    #[case("[2001:db8::1]/path", "[2001:db8::1]/path")]
    #[case(
        "[2001:db8::1]/路径/资源",
        "[2001:db8::1]/%E8%B7%AF%E5%BE%84/%E8%B5%84%E6%BA%90"
    )]
    fn test_convert_idn_to_ascii_cases(
        #[case] host_part: &str,
        #[case] expected_host_part: &str,
        #[values("tcp", "udp", "ws", "wss", "wg", "quic", "http", "https")] protocol: &str,
        #[values(false, true)] dual_convert: bool,
    ) {
        let input = url::Url::parse(&format!("{}://{}", protocol, host_part)).unwrap();
        let input = if dual_convert {
            // in case url is serialized/deserialized as string somewhere else
            input.to_string().parse().unwrap()
        } else {
            input
        };
        let actual = convert_idn_to_ascii(input.clone()).unwrap().to_string();

        let mut expected = format!("{}://{}", protocol, expected_host_part);

        // ws and wss protocols may automatically add a trailing slash if there's no path after host/port
        if input.is_special() && actual.ends_with("/") && !expected_host_part.ends_with("/") {
            expected.push('/');
        }

        assert_eq!(actual, expected);
    }
}
