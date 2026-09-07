use base64::Engine;
use hmac::{Hmac, Mac};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Invalid token format")]
    InvalidToken,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No certificates found in PEM file")]
    NoCertificatesFound,
    #[error("No private key found in PEM file")]
    NoPrivateKeyFound,
}

/// Computes the 32-bit FNV-1a hash of a string, returning an 8-character lowercase hex string.
/// Matches Go's `hash := fnv.New32a(); hash.Write([]byte(port)); hex.EncodeToString(hash.Sum(nil))`.
pub fn fnv1a_32_hex(input: &str) -> String {
    let mut hash: u32 = 0x811c9dc5;
    for &b in input.as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    format!("{:08x}", hash)
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate as a lowercase hex string.
/// Matches Go's `FormatCertFingerprint(certRaw)`.
pub fn format_cert_fingerprint(cert_raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_raw);
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Obfuscates/deobfuscates data in-place using TunnelKey as a repeating cipher key.
pub fn xor_inplace(data: &mut [u8], tunnel_key: &[u8]) {
    if tunnel_key.is_empty() {
        return;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= tunnel_key[i % tunnel_key.len()];
    }
}

/// Encodes signal data: XOR with tunnel_key -> Base64 StdEncode -> append '\n'.
pub fn encode_signal(data: &[u8], tunnel_key: &[u8]) -> Vec<u8> {
    let mut obfuscated = data.to_vec();
    xor_inplace(&mut obfuscated, tunnel_key);
    let mut encoded = base64::engine::general_purpose::STANDARD
        .encode(&obfuscated)
        .into_bytes();
    encoded.push(b'\n');
    encoded
}

/// Decodes signal data: strip trailing newline -> Base64 decode -> XOR deobfuscate.
pub fn decode_signal(raw: &[u8], tunnel_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let trimmed = match raw.strip_suffix(b"\r\n") {
        Some(t) => t,
        None => raw.strip_suffix(b"\n").unwrap_or(raw),
    };
    let mut decoded = base64::engine::general_purpose::STANDARD.decode(trimmed)?;
    xor_inplace(&mut decoded, tunnel_key);
    Ok(decoded)
}

/// Produces an HMAC-SHA256 authentication token derived from tunnel_key.
/// `hex(HMAC-SHA256(key = tunnel_key, msg = tunnel_key))`.
pub fn generate_auth_token(tunnel_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(tunnel_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(tunnel_key.as_bytes());
    let result = mac.finalize();
    hex_encode(&result.into_bytes())
}

/// Constant-time byte slice comparison to resist timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Performs constant-time comparison of the provided token against the expected token.
pub fn verify_auth_token(token: &str, tunnel_key: &str) -> bool {
    let expected = generate_auth_token(tunnel_key);
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

/// Checks whether an HTTP Basic Proxy-Authorization header carries credentials starting with `<tunnel_key>:`.
pub fn verify_pre_auth(header_value: &str, tunnel_key: &str) -> bool {
    let prefix = "Basic ";
    if !header_value.starts_with(prefix) {
        return false;
    }
    let b64 = &header_value[prefix.len()..];
    if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
            let expected_prefix = format!("{}:", tunnel_key);
            return decoded_str.starts_with(&expected_prefix);
        }
    }
    false
}

/// Generates an ephemeral ECDSA P-256 self-signed certificate and private key in RAM.
pub fn generate_ephemeral_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CryptoError> {
    let params = CertificateParams::new(vec!["localhost".to_string(), "nodepass".to_string()])?;
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}

fn extract_pem_block(
    content: &str,
    begin_tag: &str,
    end_tag: &str,
) -> Result<Option<Vec<u8>>, CryptoError> {
    if let Some(start_idx) = content.find(begin_tag) {
        let after_begin = &content[start_idx + begin_tag.len()..];
        if let Some(end_idx) = after_begin.find(end_tag) {
            let inner = &after_begin[..end_idx];
            // Skip any RFC 1421 / OpenSSL headers (e.g. "Proc-Type: ...") before the blank line
            let b64_part = if let Some(pos) = inner.find("\r\n\r\n") {
                &inner[pos + 4..]
            } else if let Some(pos) = inner.find("\n\n") {
                &inner[pos + 2..]
            } else {
                inner
            };
            let b64_str: String = b64_part.chars().filter(|c| !c.is_whitespace()).collect();
            let der = base64::engine::general_purpose::STANDARD.decode(&b64_str)?;
            return Ok(Some(der));
        }
    }
    Ok(None)
}

/// Loads one or more X.509 certificates from a PEM file.
pub fn load_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, CryptoError> {
    let content = std::fs::read_to_string(path)?;
    let mut certs = Vec::new();
    let begin_tag = "-----BEGIN CERTIFICATE-----";
    let end_tag = "-----END CERTIFICATE-----";

    let mut rest = content.as_str();
    while let Some(start_idx) = rest.find(begin_tag) {
        let after_begin = &rest[start_idx + begin_tag.len()..];
        if let Some(end_idx) = after_begin.find(end_tag) {
            let b64_str: String = after_begin[..end_idx]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = base64::engine::general_purpose::STANDARD.decode(&b64_str)?;
            certs.push(CertificateDer::from(der));
            rest = &after_begin[end_idx + end_tag.len()..];
        } else {
            break;
        }
    }
    if certs.is_empty() {
        return Err(CryptoError::NoCertificatesFound);
    }
    Ok(certs)
}

/// Loads a private key (PKCS#8, RSA PKCS#1, or EC SEC1) from a PEM file.
pub fn load_pem_key(path: &str) -> Result<PrivateKeyDer<'static>, CryptoError> {
    let content = std::fs::read_to_string(path)?;

    // PKCS#8
    if let Some(der) = extract_pem_block(
        &content,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
    )? {
        return Ok(PrivateKeyDer::Pkcs8(der.into()));
    }
    // RSA PKCS#1
    if let Some(der) = extract_pem_block(
        &content,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
    )? {
        return Ok(PrivateKeyDer::Pkcs1(der.into()));
    }
    // EC SEC1
    if let Some(der) = extract_pem_block(
        &content,
        "-----BEGIN EC PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
    )? {
        return Ok(PrivateKeyDer::Sec1(der.into()));
    }

    Err(CryptoError::NoPrivateKeyFound)
}

/// Loads certificates and private key from file paths.
pub fn load_certs_and_key(
    crt_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CryptoError> {
    let certs = load_pem_certs(crt_path)?;
    let key = load_pem_key(key_path)?;
    Ok((certs, key))
}

/// Creates a rustls ServerConfig using the provided certificate and private key.
pub fn create_server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, CryptoError> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    // Enable session resumption cache (L-4)
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(2048);
    Ok(config)
}

/// Creates a rustls ClientConfig for TLS Mode 1 (InsecureSkipVerify CA chain, but records peer fingerprint).
pub fn create_mode1_client_tls_config(
    recorded_fingerprint: Arc<parking_lot::Mutex<Option<String>>>,
) -> rustls::ClientConfig {
    let verifier = Arc::new(Mode1CertVerifier {
        recorded_fingerprint,
    });

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported")
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    // Enable client session resumption cache (L-4)
    config.resumption = rustls::client::Resumption::in_memory_sessions(2048);
    config
}

/// Creates a rustls ClientConfig for TLS Mode 2 (CA verified or user certs).
pub fn create_mode2_client_tls_config(
    crt_path: Option<&str>,
) -> Result<rustls::ClientConfig, CryptoError> {
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(path) = crt_path {
        if !path.is_empty() {
            if let Ok(certs) = load_pem_certs(path) {
                for cert in certs {
                    let _ = root_store.add(cert);
                }
            }
        }
    }

    let mut config = if root_store.is_empty() {
        let recorded = Arc::new(parking_lot::Mutex::new(None));
        create_mode1_client_tls_config(recorded)
    } else {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_root_certificates(root_store)
        .with_no_client_auth()
    };
    config.resumption = rustls::client::Resumption::in_memory_sessions(2048);
    Ok(config)
}

/// Custom ServerCertVerifier for TLS Mode 1.
/// Accepts any self-signed server cert, but records its SHA-256 fingerprint for subsequent signal verification.
#[derive(Debug)]
pub struct Mode1CertVerifier {
    pub recorded_fingerprint: Arc<parking_lot::Mutex<Option<String>>>,
}

impl rustls::client::danger::ServerCertVerifier for Mode1CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = format_cert_fingerprint(end_entity.as_ref());
        *self.recorded_fingerprint.lock() = Some(fp);
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
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
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
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_32_hex() {
        let h = fnv1a_32_hex("10101");
        assert_eq!(h.len(), 8);
        let h2 = fnv1a_32_hex("10101");
        assert_eq!(h, h2);
        let h_12345 = fnv1a_32_hex("12345");
        assert_eq!(h_12345.len(), 8);
    }

    #[test]
    fn test_xor_and_signal_codec() {
        let key = b"my_secret_tunnel_key";
        let original = b"{\"action\":\"tcp\",\"remote\":\"127.0.0.1:8080\",\"id\":\"12345678\"}";

        let encoded = encode_signal(original, key);
        assert!(encoded.ends_with(b"\n"));

        let decoded = decode_signal(&encoded, key).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_auth_token() {
        let key = "sample_key";
        let token = generate_auth_token(key);
        assert_eq!(token.len(), 64);
        assert!(verify_auth_token(&token, key));
        assert!(!verify_auth_token("invalid_token", key));
    }

    #[test]
    fn test_verify_pre_auth() {
        let key = "tunnel123";
        let header = "Basic dHVubmVsMTIzOnBhc3N3b3Jk";
        assert!(verify_pre_auth(header, key));

        let invalid_header = "Basic YWJjZDoxMjM=";
        assert!(!verify_pre_auth(invalid_header, key));
    }

    #[test]
    fn test_generate_ephemeral_cert_and_fingerprint() {
        let (cert, _key) = generate_ephemeral_cert().unwrap();
        let fp = format_cert_fingerprint(cert.as_ref());
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn test_load_pem_certs_and_key() {
        use std::io::Write;
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();

        // Generate an ephemeral cert and key to write out as PEM
        let params = CertificateParams::new(vec!["test.nodepass.org".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        cert_file.write_all(cert.pem().as_bytes()).unwrap();
        key_file
            .write_all(key_pair.serialize_pem().as_bytes())
            .unwrap();

        let certs = load_pem_certs(cert_file.path().to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 1);

        let key = load_pem_key(key_file.path().to_str().unwrap()).unwrap();
        match key {
            PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected PKCS8 key"),
        }

        let (c, k) = load_certs_and_key(
            cert_file.path().to_str().unwrap(),
            key_file.path().to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(c.len(), 1);
        assert!(matches!(k, PrivateKeyDer::Pkcs8(_)));
    }
}
