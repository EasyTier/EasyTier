use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn init_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

pub fn get_insecure_tls_client_config() -> rustls::ClientConfig {
    init_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider.clone()))
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config
}

pub fn get_insecure_tls_cert<'a>() -> (Vec<CertificateDer<'a>>, PrivateKeyDer<'a>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key);
    let cert_chain = vec![cert_der.clone().into()];

    (cert_chain, priv_key.into())
}

fn get_secure_tls_client_config() -> rustls::ClientConfig {
    init_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().expect("could not load system certs");
    root_store.add_parsable_certificates(certs);

    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

pub fn get_tls_client_config_by_url(url: &url::Url) -> rustls::ClientConfig {
    let is_insecure = url.query_pairs().any(|(k, v)| k == "insecure" && v == "1");
    let host_is_ip = match url.host() {
        Some(url::Host::Ipv4(_)) => true,
        Some(url::Host::Ipv6(_)) => true,
        Some(url::Host::Domain(_)) => false,
        None => false,
    };

    if is_insecure || host_is_ip {
        get_insecure_tls_client_config()
    } else {
        get_secure_tls_client_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use url::Url;

    #[rstest]
    #[case("wss://127.0.0.1", true)] // host is ipv4, should be insecure
    #[case("wss://[::1]", true)] // host is ipv6, should be insecure
    #[case("wss://example.com", false)] // host is domain, no insecure=1, should be secure
    #[case("wss://example.com?insecure=1", true)] // insecure=1, should be insecure
    fn test_get_tls_client_config_by_url(#[case] url_str: &str, #[case] expect_insecure: bool) {
        let expect_config = if expect_insecure {
            get_insecure_tls_client_config()
        } else {
            get_secure_tls_client_config()
        };
        let url = Url::parse(url_str).unwrap();
        let config = get_tls_client_config_by_url(&url);
        assert_eq!(format!("{:?}", config), format!("{:?}", expect_config));
    }
}
