use crate::{
    authentication::registry_based, cert_verification::CertificateVerifier,
    settings::TlsHostsSettings, utils::ToTomlComment,
};
#[cfg(feature = "rt_doc")]
use macros::{Getter, RuntimeDoc};
use once_cell::sync::Lazy;
use toml_edit::{value, Document};

pub fn build(
    client: &String,
    addresses: Vec<String>,
    username: &[registry_based::Client],
    hostsettings: &TlsHostsSettings,
    custom_sni: Option<String>,
    client_random_prefix: Option<String>,
) -> ClientConfig {
    let user = username
        .iter()
        .find(|x| x.username == *client)
        .expect("There is no user config for specified username");

    let host = hostsettings
        .main_hosts
        .first()
        .expect("Can't find main host inside hosts config");

    let certificate =
        std::fs::read_to_string(&host.cert_chain_path).expect("Failed to load certificate");

    // Check if certificate is system-verifiable
    let cert_is_system_verifiable = CertificateVerifier::new()
        .ok()
        .map(|verifier| verifier.is_system_verifiable(&host.cert_chain_path, &host.hostname))
        .unwrap_or(false);

    ClientConfig {
        hostname: host.hostname.clone(),
        addresses,
        custom_sni: custom_sni.unwrap_or_default(),
        has_ipv6: true, // Hardcoded to true, client could change this himself
        username: user.username.clone(),
        password: user.password.clone(),
        client_random_prefix: client_random_prefix.unwrap_or_default(),
        skip_verification: false,
        certificate,
        cert_is_system_verifiable,
        upstream_protocol: "http2".into(),
        anti_dpi: false,
    }
}

#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct ClientConfig {
    /// Endpoint host name, used for TLS session establishment
    hostname: String,
    /// Endpoint addresses in `IP:port` or `hostname:port` format
    addresses: Vec<String>,
    /// Custom SNI value for TLS handshake.
    /// If set, this value is used as the TLS SNI instead of the hostname.
    custom_sni: String,
    /// Whether IPv6 traffic can be routed through the endpoint
    has_ipv6: bool,
    /// Username for authorization
    username: String,
    /// Password for authorization
    password: String,
    /// TLS client random hex prefix for connection filtering.
    /// Must have a corresponding rule in rules.toml.
    client_random_prefix: String,
    /// Skip the endpoint certificate verification?
    /// That is, any certificate is accepted with this one set to true.
    skip_verification: bool,
    /// Endpoint certificate in PEM format.
    /// If not specified, the endpoint certificate is verified using the system storage.
    certificate: String,
    /// True if cert can be verified by system CAs (used to omit cert from deep-link)
    cert_is_system_verifiable: bool,
    /// Protocol to be used to communicate with the endpoint [http2, http3]
    upstream_protocol: String,
    /// Is anti-DPI measures should be enabled
    anti_dpi: bool,
}

impl ClientConfig {
    pub fn compose_toml(&self) -> String {
        let mut doc: Document = TEMPLATE.parse().unwrap();
        doc["hostname"] = value(&self.hostname);
        let vec = toml_edit::Array::from_iter(self.addresses.iter().map(|x| x.as_str()));
        doc["addresses"] = value(vec);
        doc["custom_sni"] = value(&self.custom_sni);
        doc["has_ipv6"] = value(self.has_ipv6);
        doc["username"] = value(&self.username);
        doc["password"] = value(&self.password);
        doc["client_random_prefix"] = value(&self.client_random_prefix);
        doc["skip_verification"] = value(self.skip_verification);
        doc["certificate"] = value(&self.certificate);
        doc["upstream_protocol"] = value(&self.upstream_protocol);
        doc["anti_dpi"] = value(self.anti_dpi);
        doc.to_string()
    }

    /// Generate a deep-link URI (tt://) for this client configuration.
    pub fn compose_deeplink(&self) -> std::io::Result<String> {
        use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

        // Convert certificate from PEM to DER if needed
        let certificate = if !self.cert_is_system_verifiable && !self.certificate.is_empty() {
            Some(
                trusttunnel_deeplink::cert::pem_to_der(&self.certificate)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            )
        } else {
            None
        };

        // Parse protocol
        let upstream_protocol: Protocol = self
            .upstream_protocol
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // Build deep-link config
        let config = DeepLinkConfig {
            hostname: self.hostname.clone(),
            addresses: self.addresses.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            client_random_prefix: if self.client_random_prefix.is_empty() {
                None
            } else {
                Some(self.client_random_prefix.clone())
            },
            custom_sni: if self.custom_sni.is_empty() {
                None
            } else {
                Some(self.custom_sni.clone())
            },
            has_ipv6: self.has_ipv6,
            skip_verification: self.skip_verification,
            certificate,
            upstream_protocol,
            anti_dpi: self.anti_dpi,
        };

        trusttunnel_deeplink::encode(&config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

static TEMPLATE: Lazy<String> = Lazy::new(|| {
    format!(
        r#"
# This file was automatically generated by endpoint and could be used in vpn client.

{}
hostname = ""

{}
addresses = []

{}
custom_sni = ""

{}
has_ipv6 = true

{}
username = ""

{}
password = ""

{}
client_random_prefix = ""

{}
skip_verification = false

{}
certificate = ""

{}
upstream_protocol = ""

{}
anti_dpi = false
"#,
        ClientConfig::doc_hostname().to_toml_comment(),
        ClientConfig::doc_addresses().to_toml_comment(),
        ClientConfig::doc_custom_sni().to_toml_comment(),
        ClientConfig::doc_has_ipv6().to_toml_comment(),
        ClientConfig::doc_username().to_toml_comment(),
        ClientConfig::doc_password().to_toml_comment(),
        ClientConfig::doc_client_random_prefix().to_toml_comment(),
        ClientConfig::doc_skip_verification().to_toml_comment(),
        ClientConfig::doc_certificate().to_toml_comment(),
        ClientConfig::doc_upstream_protocol().to_toml_comment(),
        ClientConfig::doc_anti_dpi().to_toml_comment(),
    )
});
