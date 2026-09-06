use crate::crypto::fnv1a_32_hex;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use url::Url;

pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300); // 5m
pub const DEFAULT_MIN_POOL: usize = 64;
pub const DEFAULT_MAX_POOL: usize = 1024;
pub const DEFAULT_SERVER_NAME: &str = "none";
pub const DEFAULT_LB_STRATEGY: &str = "0";
pub const DEFAULT_RUN_MODE: &str = "0";
pub const DEFAULT_POOL_TYPE: &str = "0";
pub const DEFAULT_DIALER_IP: &str = "auto";
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::ZERO;
pub const DEFAULT_RATE_LIMIT: u64 = 0;
pub const DEFAULT_SLOT_LIMIT: i32 = 65536;
pub const DEFAULT_PROXY_PROTOCOL: &str = "0";
pub const DEFAULT_BLOCK_PROTOCOL: &str = "0";
pub const DEFAULT_TCP_STRATEGY: &str = "0";
pub const DEFAULT_UDP_STRATEGY: &str = "0";

// Runtime timing constants matching Go
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
pub const UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
pub const UDP_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const POOL_GET_TIMEOUT: Duration = Duration::from_secs(5);
pub const MIN_POOL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_POOL_INTERVAL: Duration = Duration::from_secs(1);
pub const REPORT_INTERVAL: Duration = Duration::from_secs(5);
pub const FALLBACK_INTERVAL: Duration = Duration::from_secs(300);
pub const SERVICE_COOLDOWN: Duration = Duration::from_secs(3);
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Missing tunnel address")]
    MissingTunnelAddr,
    #[error("Missing target address")]
    MissingTargetAddr,
    #[error("Tunnel port {port} conflicts with target {target}")]
    PortConflict { port: u16, target: String },
    #[error("Invalid parameter '{param}': {reason}")]
    InvalidParam { param: String, reason: String },
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub raw_url: String,
    pub core_type: String, // "server", "client", "master"
    pub tunnel_addr: String, // e.g. "0.0.0.0:10101" or "example.com:10101"
    pub server_name: String, // TLS SNI or "none"
    pub server_port: u16,
    pub tunnel_key: String,
    pub target_addrs: Vec<String>,
    pub dns_cache_ttl: Duration,
    pub lb_strategy: String,
    pub min_pool_capacity: usize,
    pub max_pool_capacity: usize,
    pub run_mode: String,
    pub pool_type: String, // "0"=TCP, "1"=QUIC, "2"=WS, "3"=H2
    pub tls_code: String,  // "0", "1", "2"
    pub crt_path: Option<String>,
    pub key_path: Option<String>,
    pub dialer_ip: String,
    pub read_timeout: Duration,
    pub rate_limit: u64, // in bytes/s (converted from Mbit/s * 125_000)
    pub slot_limit: i32,
    pub proxy_protocol: String,
    pub block_protocol: String,
    pub block_socks: bool,
    pub block_http: bool,
    pub block_tls: bool,
    pub disable_tcp: bool,
    pub disable_udp: bool,
    pub log_level: String,
    pub data_flow: String, // "+" or "-"
}

impl TunnelConfig {
    pub fn parse(url_str: &str) -> Result<Self, ConfigError> {
        let url = Url::parse(url_str).map_err(|e| ConfigError::InvalidUrl(e.to_string()))?;
        let core_type = url.scheme().to_lowercase();
        if core_type != "server" && core_type != "client" && core_type != "master" {
            return Err(ConfigError::InvalidUrl(format!("unknown scheme: {}", core_type)));
        }

        let host = url.host_str().ok_or(ConfigError::MissingTunnelAddr)?;
        let port = url.port().ok_or(ConfigError::MissingTunnelAddr)?;
        let tunnel_addr = format!("{}:{}", host, port);

        // TunnelKey derivation
        let tunnel_key = if !url.username().is_empty() {
            url.username().to_string()
        } else {
            fnv1a_32_hex(&port.to_string())
        };

        // Query parameters
        let mut sni = None;
        let mut dns_cache_ttl = DEFAULT_DNS_TTL;
        let mut lb_strategy = DEFAULT_LB_STRATEGY.to_string();
        let mut min_pool = DEFAULT_MIN_POOL;
        let mut max_pool = DEFAULT_MAX_POOL;
        let mut run_mode = DEFAULT_RUN_MODE.to_string();
        let mut pool_type = DEFAULT_POOL_TYPE.to_string();
        let mut tls_code = "0".to_string();
        let mut crt_path = None;
        let mut key_path = None;
        let mut dialer_ip = DEFAULT_DIALER_IP.to_string();
        let mut read_timeout = DEFAULT_READ_TIMEOUT;
        let mut rate_limit = DEFAULT_RATE_LIMIT;
        let mut slot_limit = DEFAULT_SLOT_LIMIT;
        let mut proxy_protocol = DEFAULT_PROXY_PROTOCOL.to_string();
        let mut block_protocol = DEFAULT_BLOCK_PROTOCOL.to_string();
        let mut disable_tcp = false;
        let mut disable_udp = false;
        let mut log_level = "info".to_string();

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "sni" => sni = Some(v.to_string()),
                "dns" => {
                    if let Some(d) = parse_duration(&v) {
                        dns_cache_ttl = d;
                    }
                }
                "lbs" => lb_strategy = v.to_string(),
                "min" => {
                    if let Ok(n) = v.parse::<usize>() {
                        if n > 0 {
                            min_pool = n;
                        }
                    }
                }
                "max" => {
                    if let Ok(n) = v.parse::<usize>() {
                        if n > 0 {
                            max_pool = n;
                        }
                    }
                }
                "mode" => run_mode = v.to_string(),
                "type" => pool_type = v.to_string(),
                "tls" => tls_code = v.to_string(),
                "crt" => crt_path = Some(v.to_string()),
                "key" => key_path = Some(v.to_string()),
                "dial" => {
                    if v != "auto" {
                        if v.parse::<IpAddr>().is_ok() {
                            dialer_ip = v.to_string();
                        }
                    }
                }
                "read" => {
                    if let Some(d) = parse_duration(&v) {
                        read_timeout = d;
                    }
                }
                "rate" => {
                    if let Ok(mbps) = v.parse::<u64>() {
                        rate_limit = mbps * 125_000;
                    }
                }
                "slot" => {
                    if let Ok(s) = v.parse::<i32>() {
                        slot_limit = s;
                    }
                }
                "proxy" => proxy_protocol = v.to_string(),
                "block" => block_protocol = v.to_string(),
                "notcp" => disable_tcp = v == "1",
                "noudp" => disable_udp = v == "1",
                "log" => log_level = v.to_string(),
                _ => {}
            }
        }

        // ServerName derivation
        let server_name = if let Some(s) = sni {
            s
        } else if host.parse::<IpAddr>().is_ok() || host.is_empty() {
            DEFAULT_SERVER_NAME.to_string()
        } else {
            host.to_string()
        };

        // QUIC (type=1) and WebSocket (type=2) require TLS
        if (pool_type == "1" || pool_type == "2") && tls_code == "0" {
            tls_code = "1".to_string();
        }

        // Target address parsing (path part)
        let raw_targets = url.path().trim_start_matches('/');
        let target_addrs: Vec<String> = if raw_targets.is_empty() {
            if core_type == "master" {
                Vec::new()
            } else {
                return Err(ConfigError::MissingTargetAddr);
            }
        } else {
            raw_targets
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        if core_type != "master" && target_addrs.is_empty() {
            return Err(ConfigError::MissingTargetAddr);
        }

        // Conflict check: tunnel port == target port on loopback
        for target in &target_addrs {
            if let Ok(target_addr) = target.parse::<SocketAddr>() {
                if target_addr.port() == port
                    && (target_addr.ip().is_loopback() || host == "0.0.0.0" || host == "::")
                {
                    return Err(ConfigError::PortConflict {
                        port,
                        target: target.clone(),
                    });
                }
            }
        }

        let block_socks = block_protocol.contains('1');
        let block_http = block_protocol.contains('2');
        let block_tls = block_protocol.contains('3');

        Ok(Self {
            raw_url: url_str.to_string(),
            core_type,
            tunnel_addr,
            server_name,
            server_port: port,
            tunnel_key,
            target_addrs,
            dns_cache_ttl,
            lb_strategy,
            min_pool_capacity: min_pool,
            max_pool_capacity: max_pool,
            run_mode,
            pool_type,
            tls_code,
            crt_path,
            key_path,
            dialer_ip,
            read_timeout,
            rate_limit,
            slot_limit,
            proxy_protocol,
            block_protocol,
            block_socks,
            block_http,
            block_tls,
            disable_tcp,
            disable_udp,
            log_level,
            data_flow: "+".to_string(),
        })
    }

    pub fn to_url_string(&self) -> String {
        let targets = self.target_addrs.join(",");
        let mut s = format!("{}://{}@{}/{}", self.core_type, self.tunnel_key, self.tunnel_addr, targets);
        let mut query = Vec::new();

        query.push(format!("dns={}", format_duration(self.dns_cache_ttl)));
        if self.server_name != DEFAULT_SERVER_NAME {
            query.push(format!("sni={}", self.server_name));
        }
        query.push(format!("lbs={}", self.lb_strategy));
        query.push(format!("min={}", self.min_pool_capacity));
        query.push(format!("max={}", self.max_pool_capacity));
        query.push(format!("mode={}", self.run_mode));
        query.push(format!("type={}", self.pool_type));
        query.push(format!("tls={}", self.tls_code));
        if let Some(ref crt) = self.crt_path {
            query.push(format!("crt={}", crt));
        }
        if let Some(ref key) = self.key_path {
            query.push(format!("key={}", key));
        }
        query.push(format!("dial={}", self.dialer_ip));
        query.push(format!("read={}", format_duration(self.read_timeout)));
        query.push(format!("rate={}", self.rate_limit / 125_000));
        query.push(format!("slot={}", self.slot_limit));
        query.push(format!("proxy={}", self.proxy_protocol));
        query.push(format!("block={}", self.block_protocol));
        if self.disable_tcp {
            query.push("notcp=1".to_string());
        }
        if self.disable_udp {
            query.push("noudp=1".to_string());
        }
        query.push(format!("log={}", self.log_level));

        if !query.is_empty() {
            s.push('?');
            s.push_str(&query.join("&"));
        }
        s
    }
}

pub fn parse_duration(s: &str) -> Option<Duration> {
    if s == "0" || s.is_empty() {
        return Some(Duration::ZERO);
    }
    let s = s.trim();
    if let Some(stripped) = s.strip_suffix("ms") {
        stripped.parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(stripped) = s.strip_suffix('s') {
        stripped.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(stripped) = s.strip_suffix('m') {
        stripped.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(stripped) = s.strip_suffix('h') {
        stripped.parse::<u64>().ok().map(|h| Duration::from_secs(h * 3600))
    } else if let Ok(sec) = s.parse::<u64>() {
        Some(Duration::from_secs(sec))
    } else {
        None
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs == 0 {
        "0s".to_string()
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_server_url() {
        let url = "server://0.0.0.0:10101/127.0.0.1:8080?log=debug&tls=1&type=0";
        let cfg = TunnelConfig::parse(url).unwrap();
        assert_eq!(cfg.core_type, "server");
        assert_eq!(cfg.tunnel_addr, "0.0.0.0:10101");
        assert_eq!(cfg.server_port, 10101);
        assert_eq!(cfg.target_addrs, vec!["127.0.0.1:8080"]);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.tls_code, "1");
        assert_eq!(cfg.pool_type, "0");
        assert_eq!(cfg.tunnel_key, fnv1a_32_hex("10101"));
    }

    #[test]
    fn test_parse_client_with_auth_and_targets() {
        let url = "client://mypassword@server.com:10101/10.0.0.1:80,10.0.0.2:80?lbs=1&rate=50&block=12";
        let cfg = TunnelConfig::parse(url).unwrap();
        assert_eq!(cfg.core_type, "client");
        assert_eq!(cfg.tunnel_key, "mypassword");
        assert_eq!(cfg.server_name, "server.com");
        assert_eq!(cfg.target_addrs.len(), 2);
        assert_eq!(cfg.lb_strategy, "1");
        assert_eq!(cfg.rate_limit, 50 * 125_000);
        assert!(cfg.block_socks);
        assert!(cfg.block_http);
        assert!(!cfg.block_tls);
    }

    #[test]
    fn test_port_conflict_detection() {
        let url = "server://0.0.0.0:8080/127.0.0.1:8080";
        let result = TunnelConfig::parse(url);
        assert!(result.is_err());
        match result {
            Err(ConfigError::PortConflict { port, .. }) => assert_eq!(port, 8080),
            _ => panic!("expected PortConflict error"),
        }
    }

    #[test]
    fn test_quic_tls_upgrade() {
        let url = "server://0.0.0.0:10101/127.0.0.1:8080?type=1&tls=0";
        let cfg = TunnelConfig::parse(url).unwrap();
        assert_eq!(cfg.tls_code, "1"); // upgraded from 0 to 1
    }
}
