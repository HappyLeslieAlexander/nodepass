use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone)]
struct DnsEntry {
    addr: SocketAddr,
    expires_at: Instant,
}

/// Thread-safe DNS cache with configurable TTL.
#[derive(Debug, Clone)]
pub struct DnsCache {
    ttl: Duration,
    entries: Arc<RwLock<HashMap<String, DnsEntry>>>,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolves `host_port` (e.g. "example.com:8080" or "1.2.3.4:8080"), using cached entry if still valid.
    pub async fn resolve(&self, host_port: &str) -> io::Result<SocketAddr> {
        let now = Instant::now();

        // Fast path: direct IP parse without caching
        if let Ok(addr) = host_port.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Cache lookup
        {
            let lock = self.entries.read();
            if let Some(entry) = lock.get(host_port) {
                if entry.expires_at > now {
                    return Ok(entry.addr);
                }
            }
        }

        // Resolve via tokio
        let mut iter = tokio::net::lookup_host(host_port).await?;
        let addr = iter
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses found"))?;

        if self.ttl > Duration::ZERO {
            let mut lock = self.entries.write();
            lock.insert(
                host_port.to_string(),
                DnsEntry {
                    addr,
                    expires_at: now + self.ttl,
                },
            );
        }

        Ok(addr)
    }
}

/// Target selector supporting Round-Robin ("0"), Latency-Based ("1"), and Failover ("2").
#[derive(Debug)]
pub struct TargetSelector {
    targets: Vec<String>,
    strategy: String,
    dns_cache: DnsCache,
    rr_index: AtomicUsize,
    best_target_idx: AtomicUsize,
    last_fallback: AtomicU64, // Unix timestamp in seconds
    fallback_interval: Duration,
}

impl TargetSelector {
    pub fn new(
        targets: Vec<String>,
        strategy: impl Into<String>,
        dns_cache: DnsCache,
        fallback_interval: Duration,
    ) -> Self {
        Self {
            targets,
            strategy: strategy.into(),
            dns_cache,
            rr_index: AtomicUsize::new(0),
            best_target_idx: AtomicUsize::new(0),
            last_fallback: AtomicU64::new(0),
            fallback_interval,
        }
    }

    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Selects the next target string and resolves it to a SocketAddr.
    pub async fn select_next(&self) -> io::Result<(String, SocketAddr)> {
        if self.targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no targets configured",
            ));
        }

        let target_str = match self.strategy.as_str() {
            "1" => {
                // Optimal-latency
                let idx = self.best_target_idx.load(Ordering::Relaxed) % self.targets.len();
                &self.targets[idx]
            }
            "2" => {
                // Primary-backup failover
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last = self.last_fallback.load(Ordering::Relaxed);
                if now.saturating_sub(last) >= self.fallback_interval.as_secs() {
                    // Reset to primary
                    self.rr_index.store(0, Ordering::Relaxed);
                }
                let idx = self.rr_index.load(Ordering::Relaxed) % self.targets.len();
                &self.targets[idx]
            }
            _ => {
                // Strategy 0: Round-robin
                let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) % self.targets.len();
                &self.targets[idx]
            }
        };

        match self.dns_cache.resolve(target_str).await {
            Ok(addr) => Ok((target_str.clone(), addr)),
            Err(e) => {
                // Failover on resolution failure
                if self.targets.len() > 1 {
                    for target in &self.targets {
                        if target != target_str {
                            if let Ok(addr) = self.dns_cache.resolve(target).await {
                                return Ok((target.clone(), addr));
                            }
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Marks the current target as failed for failover strategy.
    pub fn mark_failure(&self) {
        if self.strategy == "2" {
            self.rr_index.fetch_add(1, Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.last_fallback.store(now, Ordering::Relaxed);
        }
    }

    /// Probes all targets via TCP connect latency and updates the lowest-latency target.
    pub async fn probe_best_target(&self, timeout: Duration) -> i64 {
        if self.targets.is_empty() {
            return -1;
        }

        let mut best_idx = 0;
        let mut min_latency = Duration::from_secs(999);

        for (idx, target) in self.targets.iter().enumerate() {
            if let Ok(addr) = self.dns_cache.resolve(target).await {
                if let Some(rtt) = tcp_ping(addr, timeout).await {
                    if rtt < min_latency {
                        min_latency = rtt;
                        best_idx = idx;
                    }
                }
            }
        }

        if min_latency < Duration::from_secs(999) {
            self.best_target_idx.store(best_idx, Ordering::Relaxed);
            min_latency.as_millis() as i64
        } else {
            -1
        }
    }
}

/// Measures TCP connection establishment round-trip time.
pub async fn tcp_ping(addr: SocketAddr, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed()),
        _ => None,
    }
}

/// Creates a TcpSocket optionally bound to a specific local source IP.
pub fn create_tcp_socket_bound(dialer_ip: &str, target_addr: SocketAddr) -> io::Result<TcpSocket> {
    let socket = match target_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    if dialer_ip != "auto" && !dialer_ip.is_empty() {
        if let Ok(ip) = dialer_ip.parse::<IpAddr>() {
            let bind_addr = SocketAddr::new(ip, 0);
            socket.bind(bind_addr)?;
        }
    }

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache_direct_ip() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let addr = cache.resolve("127.0.0.1:8080").await.unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn test_target_selector_round_robin() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let targets = vec!["127.0.0.1:8081".to_string(), "127.0.0.1:8082".to_string()];
        let selector = TargetSelector::new(targets, "0", cache, Duration::from_secs(300));

        let (t1, a1) = selector.select_next().await.unwrap();
        assert_eq!(t1, "127.0.0.1:8081");
        assert_eq!(a1.port(), 8081);

        let (t2, a2) = selector.select_next().await.unwrap();
        assert_eq!(t2, "127.0.0.1:8082");
        assert_eq!(a2.port(), 8082);

        let (t3, a3) = selector.select_next().await.unwrap();
        assert_eq!(t3, "127.0.0.1:8081");
        assert_eq!(a3.port(), 8081);
    }
}
