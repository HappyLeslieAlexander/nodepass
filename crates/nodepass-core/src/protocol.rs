use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Wire format for control messages exchanged over the control connection.
/// Matches Go Signal struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Signal {
    #[serde(rename = "action")]
    pub action_type: String,

    #[serde(rename = "remote", skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,

    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub pool_conn_id: Option<String>,

    #[serde(rename = "fp", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl Signal {
    pub fn new(action_type: impl Into<String>) -> Self {
        Self {
            action_type: action_type.into(),
            remote_addr: None,
            pool_conn_id: None,
            fingerprint: None,
        }
    }

    pub fn tcp(remote: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            action_type: "tcp".to_string(),
            remote_addr: Some(remote.into()),
            pool_conn_id: Some(id.into()),
            fingerprint: None,
        }
    }

    pub fn udp(remote: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            action_type: "udp".to_string(),
            remote_addr: Some(remote.into()),
            pool_conn_id: Some(id.into()),
            fingerprint: None,
        }
    }

    pub fn verify(id: impl Into<String>, fp: impl Into<String>) -> Self {
        Self {
            action_type: "verify".to_string(),
            remote_addr: None,
            pool_conn_id: Some(id.into()),
            fingerprint: Some(fp.into()),
        }
    }

    pub fn ping() -> Self {
        Self::new("ping")
    }

    pub fn pong() -> Self {
        Self::new("pong")
    }

    pub fn flush() -> Self {
        Self::new("flush")
    }
}

/// Generates a PROXY protocol v1 header line.
/// Format: "PROXY TCP4|TCP6 <srcIP> <dstIP> <srcPort> <dstPort>\r\n"
pub fn format_proxy_v1_header(client_addr: SocketAddr, remote_addr: SocketAddr) -> String {
    let proto = match (client_addr, remote_addr) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
        (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
        _ => "UNKNOWN",
    };

    if proto == "UNKNOWN" {
        return "PROXY UNKNOWN\r\n".to_string();
    }

    format!(
        "PROXY {} {} {} {} {}\r\n",
        proto,
        client_addr.ip(),
        remote_addr.ip(),
        client_addr.port(),
        remote_addr.port()
    )
}

/// Detects application protocol by inspecting up to 8 initial bytes.
/// Returns protocol name ("SOCKS4", "SOCKS5", "HTTP", "TLS") if detected and blocked,
/// or None if allowed.
///
/// Signatures:
/// - SOCKS4: b[0] == 0x04 && (b[1] == 0x01 || b[1] == 0x02)
/// - SOCKS5: b[0] == 0x05 && b[1] >= 0x01 && b[1] <= 0x03
/// - HTTP: b[0] is ASCII uppercase ('A'..='Z') and contains space within first 8 bytes
/// - TLS: b[0] == 0x16 (Handshake record)
pub fn detect_block_protocol(
    peek_bytes: &[u8],
    block_socks: bool,
    block_http: bool,
    block_tls: bool,
) -> Option<&'static str> {
    if !block_socks && !block_http && !block_tls {
        return None;
    }

    if peek_bytes.is_empty() {
        return None;
    }

    if block_socks && peek_bytes.len() >= 2 {
        if peek_bytes[0] == 0x04 && (peek_bytes[1] == 0x01 || peek_bytes[1] == 0x02) {
            return Some("SOCKS4");
        }
        if peek_bytes[0] == 0x05 && peek_bytes[1] >= 0x01 && peek_bytes[1] <= 0x03 {
            return Some("SOCKS5");
        }
    }

    if block_http && peek_bytes.len() >= 4 && peek_bytes[0].is_ascii_uppercase() {
        for (i, &b) in peek_bytes[1..].iter().enumerate() {
            if b == b' ' {
                return Some("HTTP");
            }
            if !b.is_ascii_uppercase() || i >= 7 {
                break;
            }
        }
    }

    if block_tls && peek_bytes[0] == 0x16 {
        return Some("TLS");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_json_serialization() {
        let sig = Signal::tcp("1.2.3.4:5678", "01020304");
        let json = serde_json::to_string(&sig).unwrap();
        assert_eq!(
            json,
            r#"{"action":"tcp","remote":"1.2.3.4:5678","id":"01020304"}"#
        );

        let decoded: Signal = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, sig);

        let ping = Signal::ping();
        let ping_json = serde_json::to_string(&ping).unwrap();
        assert_eq!(ping_json, r#"{"action":"ping"}"#);

        let verify = Signal::verify("00000000", "abcdef123456");
        let verify_json = serde_json::to_string(&verify).unwrap();
        assert_eq!(
            verify_json,
            r#"{"action":"verify","id":"00000000","fp":"abcdef123456"}"#
        );
    }

    #[test]
    fn test_proxy_v1_header() {
        let client: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let remote: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let header = format_proxy_v1_header(client, remote);
        assert_eq!(header, "PROXY TCP4 192.168.1.100 10.0.0.1 54321 80\r\n");

        let client6: SocketAddr = "[2001:db8::1]:54321".parse().unwrap();
        let remote6: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let header6 = format_proxy_v1_header(client6, remote6);
        assert_eq!(header6, "PROXY TCP6 2001:db8::1 2001:db8::2 54321 80\r\n");
    }

    #[test]
    fn test_detect_block_protocol() {
        // SOCKS5: 0x05 0x01 ...
        assert_eq!(
            detect_block_protocol(&[0x05, 0x01, 0x00], true, false, false),
            Some("SOCKS5")
        );
        // SOCKS4: 0x04 0x01 ...
        assert_eq!(
            detect_block_protocol(&[0x04, 0x01, 0x00, 0x50], true, false, false),
            Some("SOCKS4")
        );
        // HTTP GET
        assert_eq!(
            detect_block_protocol(b"GET / HTTP/1.1\r\n", false, true, false),
            Some("HTTP")
        );
        // TLS Handshake: 0x16 0x03 0x03 ...
        assert_eq!(
            detect_block_protocol(&[0x16, 0x03, 0x03, 0x00], false, false, true),
            Some("TLS")
        );
        // Allowed
        assert_eq!(
            detect_block_protocol(b"RANDOM_DATA", true, true, true),
            None
        );
    }
}
