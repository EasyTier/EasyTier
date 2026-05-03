#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::TomlConfigLoader;
    use crate::common::global_ctx::GlobalCtx;
    use std::sync::Arc;

    fn get_mock_global_ctx() -> Arc<GlobalCtx> {
        let config = TomlConfigLoader::default();
        Arc::new(GlobalCtx::new(config))
    }

    #[test]
    fn test_http_ttl_parsing_default() {
        let url: url::Url = "http://example.com/nodes".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 300);
    }

    #[test]
    fn test_http_ttl_parsing_valid() {
        let url: url::Url = "http://example.com/nodes?ttl=120".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 120);
    }

    #[test]
    fn test_http_ttl_parsing_minimum() {
        let url: url::Url = "http://example.com/nodes?ttl=60".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 60);
    }

    #[test]
    fn test_http_ttl_parsing_maximum() {
        let url: url::Url = "http://example.com/nodes?ttl=6000".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 6000);
    }

    #[test]
    fn test_http_ttl_parsing_too_small() {
        let url: url::Url = "http://example.com/nodes?ttl=30".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 300); // Should use default
    }

    #[test]
    fn test_http_ttl_parsing_too_large() {
        let url: url::Url = "http://example.com/nodes?ttl=10000".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 300); // Should use default
    }

    #[test]
    fn test_http_ttl_parsing_invalid() {
        let url: url::Url = "http://example.com/nodes?ttl=abc".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 300); // Should use default
    }

    #[test]
    fn test_http_ttl_parsing_case_insensitive() {
        let url: url::Url = "http://example.com/nodes?TTL=180".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 180);
    }

    #[test]
    fn test_http_ttl_with_other_params() {
        let url: url::Url = "http://example.com/nodes?token=xyz&ttl=240&format=json".parse().unwrap();
        let connector = HttpTunnelConnector::new(url, get_mock_global_ctx());
        assert_eq!(connector.extract_ttl_from_url(), 240);
    }
}
