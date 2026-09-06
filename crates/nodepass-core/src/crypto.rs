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
    let mut mac = HmacSha256::new_from_slice(tunnel_key.as_bytes())
        .expect("HMAC can take key of any size");
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
pub fn generate_ephemeral_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CryptoError> {
    let params = CertificateParams::new(vec!["localhost".to_string(), "nodepass".to_string()])?;
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}

/// Creates a rustls ServerConfig using the provided certificate and private key.
pub fn create_server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, CryptoError> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    Ok(config)
}

/// Creates a rustls ClientConfig for TLS Mode 1 (InsecureSkipVerify CA chain, but records peer fingerprint).
pub fn create_mode1_client_tls_config(
    recorded_fingerprint: Arc<parking_lot::Mutex<Option<String>>>,
) -> rustls::ClientConfig {
    let verifier = Arc::new(Mode1CertVerifier {
        recorded_fingerprint,
    });

    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
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
}
