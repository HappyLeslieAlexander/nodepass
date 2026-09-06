use crate::control::ControlLoop;
use crate::exchange::data_exchange;
use nodepass_core::address::{DnsCache, TargetSelector};
use nodepass_core::config::{TunnelConfig, POOL_GET_TIMEOUT, REPORT_INTERVAL};
use nodepass_core::crypto::{
    format_cert_fingerprint, generate_ephemeral_cert, verify_auth_token,
};
use nodepass_core::protocol::{detect_block_protocol, format_proxy_v1_header, Signal};
use nodepass_transport::pool::{
    H2Pool, QuicPool, TcpPool, TransportPool, WsPool,
};
use nodepass_transport::rate::RateLimiter;
use nodepass_transport::stats::Stats;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct TunnelServer {
    config: Arc<parking_lot::RwLock<TunnelConfig>>,
    stats: Stats,
    dns_cache: DnsCache,
    selector: Arc<TargetSelector>,
    rate_limiter: Option<RateLimiter>,
    stop_flag: Arc<AtomicBool>,
}

impl TunnelServer {
    pub fn new(config: TunnelConfig) -> Self {
        let dns_cache = DnsCache::new(config.dns_cache_ttl);
        let selector = Arc::new(TargetSelector::new(
            config.target_addrs.clone(),
            config.lb_strategy.clone(),
            dns_cache.clone(),
            Duration::from_secs(300),
        ));
        let rate_limiter = RateLimiter::new(config.rate_limit, config.rate_limit);
        Self {
            config: Arc::new(parking_lot::RwLock::new(config)),
            stats: Stats::new(65536),
            dns_cache,
            selector,
            rate_limiter,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        // 1. Determine run mode and flow direction
        let (mut run_mode, mut data_flow) = {
            let cfg = self.config.read();
            (cfg.run_mode.clone(), cfg.data_flow.clone())
        };

        match run_mode.as_str() {
            "1" => {
                data_flow = "-".to_string();
            }
            "2" => {
                data_flow = "+".to_string();
            }
            _ => {
                // Auto mode "0": try binding target listener to see if we host the target
                let target = self.config.read().target_addrs.first().cloned().unwrap_or_default();
                if !target.is_empty() && TcpListener::bind(&target).await.is_ok() {
                    run_mode = "1".to_string();
                    data_flow = "-".to_string();
                } else {
                    run_mode = "2".to_string();
                    data_flow = "+".to_string();
                }
            }
        }

        {
            let mut cfg = self.config.write();
            cfg.run_mode = run_mode;
            cfg.data_flow = data_flow;
        }

        // 2. Perform HTTP handshake
        info!("Pending tunnel handshake...");
        let client_ip = self.perform_handshake().await?;
        debug!("Handshake completed with client IP: {}", client_ip);

        // 3. If TLS Mode 1 is active, regenerate RAM certificate with TLS 1.3
        let (tls_acceptor, new_fingerprint) = {
            let cfg = self.config.read().clone();
            if cfg.tls_code != "0" {
                let (cert, key) = generate_ephemeral_cert()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let fp = format_cert_fingerprint(&cert);
                if cfg.tls_code == "1" {
                    info!("TLS code-1: RAM cert regenerated with TLS 1.3");
                }
                let mut server_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], key)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                (Some(TlsAcceptor::from(Arc::new(server_config))), Some(fp))
            } else {
                (None, None)
            }
        };

        let cfg = self.config.read().clone();
        info!("Getting tunnel pool ready...");

        // 4. Initialize tunnel connection pool based on pool type
        let pool: Arc<dyn TransportPool> = match cfg.pool_type.as_str() {
            "1" => {
                // QUIC pool
                let quic_pool = Arc::new(QuicPool::new(cfg.max_pool_capacity));
                let (cert, key) = generate_ephemeral_cert()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut rustls_server_cfg = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], key)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                rustls_server_cfg.alpn_protocols = vec![b"np-quic".to_vec()];
                let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                    quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server_cfg)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
                ));
                let tunnel_sock_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let endpoint = quinn::Endpoint::server(server_config, tunnel_sock_addr)?;
                quic_pool.start_server(endpoint);
                quic_pool
            }
            "2" => {
                // WebSocket pool
                let ws_pool = Arc::new(WsPool::new(cfg.max_pool_capacity));
                let listener = TcpListener::bind(&cfg.tunnel_addr).await?;
                ws_pool.start_server(listener, tls_acceptor.clone());
                ws_pool
            }
            "3" => {
                // HTTP/2 pool
                let h2_pool = Arc::new(H2Pool::new(cfg.max_pool_capacity));
                let listener = TcpListener::bind(&cfg.tunnel_addr).await?;
                let h2_pool_clone = Arc::clone(&h2_pool);
                let tls_acc = tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok((tcp_stream, _)) = listener.accept().await {
                        if let Some(ref acc) = tls_acc {
                            if let Ok(tls_stream) = acc.accept(tcp_stream).await {
                                h2_pool_clone.start_server(tls_stream);
                            }
                        } else {
                            h2_pool_clone.start_server(tcp_stream);
                        }
                    }
                });
                h2_pool
            }
            _ => {
                // TCP pool (type 0)
                let (tcp_pool, _) = TcpPool::new(cfg.max_pool_capacity);
                let listener = TcpListener::bind(&cfg.tunnel_addr).await?;
                tcp_pool.start_server(listener, tls_acceptor.clone());
                Arc::new(tcp_pool)
            }
        };

        // 5. Claim control connection
        let control_conn = pool.outgoing_get("00000000", POOL_GET_TIMEOUT).await
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, format!("set control conn failed: {}", e)))?;

        info!("Marking tunnel handshake as complete");

        // 6. Start control loop
        let control_loop = Arc::new(ControlLoop::new(cfg.tunnel_key.clone(), Arc::clone(&pool)));
        control_loop.start(control_conn, REPORT_INTERVAL, cfg.tls_code == "1");

        // If TLS code 1, send verify signal with new fingerprint
        if cfg.tls_code == "1" {
            if let Some(fp) = new_fingerprint {
                let _ = control_loop.send_signal(Signal::verify("00000000", fp)).await;
            }
        }

        // 7. If data_flow == "-", listen on target address and send signals into tunnel
        if cfg.data_flow == "-" {
            let pool_clone = Arc::clone(&pool);
            let control_tx = control_loop.sender();
            let cfg_clone = cfg.clone();
            let stats_clone = self.stats.clone();

            tokio::spawn(async move {
                if let Some(target) = cfg_clone.target_addrs.first() {
                    if let Ok(listener) = TcpListener::bind(target).await {
                        while let Ok((target_conn, remote_addr)) = listener.accept().await {
                            if !stats_clone.try_acquire_slot(false) {
                                warn!("TCP slot limit reached on target listener");
                                continue;
                            }

                            // Protocol peek detection
                            let mut peek_buf = [0u8; 8];
                            if let Ok(n) = target_conn.peek(&mut peek_buf).await {
                                if let Some(proto) = detect_block_protocol(
                                    &peek_buf[..n],
                                    cfg_clone.block_socks,
                                    cfg_clone.block_http,
                                    cfg_clone.block_tls,
                                ) {
                                    warn!("Blocked protocol {} from {}", proto, remote_addr);
                                    stats_clone.release_slot(false);
                                    continue;
                                }
                            }

                            let pool = Arc::clone(&pool_clone);
                            let control_tx = control_tx.clone();
                            let stats = stats_clone.clone();
                            let read_timeout = cfg_clone.read_timeout;

                            tokio::spawn(async move {
                                if let Ok((id, pool_conn)) = pool.incoming_get(POOL_GET_TIMEOUT).await {
                                    let _ = control_tx.send(Signal::tcp(remote_addr.to_string(), id)).await;
                                    let _ = data_exchange(target_conn, pool_conn, read_timeout, 16384).await;
                                }
                                stats.release_slot(false);
                            });
                        }
                    }
                }
            });
        }

        // 8. Signal dispatcher loop
        let selector = Arc::clone(&self.selector);
        let stats = self.stats.clone();
        let proxy_enabled = cfg.proxy_protocol == "1";
        let read_timeout = cfg.read_timeout;

        while let Some(signal) = control_loop.recv_signal().await {
            match signal.action_type.as_str() {
                "tcp" => {
                    // When data_flow is "+", incoming user connections arrive at the client,
                    // which sends a "tcp" signal to the server to forward to target.
                    if let Some(id) = signal.pool_conn_id {
                        let pool_clone = Arc::clone(&pool);
                        let selector = Arc::clone(&selector);
                        let stats = stats.clone();
                        let remote_addr_str = signal.remote_addr.unwrap_or_default();

                        tokio::spawn(async move {
                            if let Ok(pool_conn) = pool_clone.outgoing_get(&id, POOL_GET_TIMEOUT).await {
                                if stats.try_acquire_slot(false) {
                                    if let Ok((_, target_addr)) = selector.select_next().await {
                                        if let Ok(mut target_conn) = TcpStream::connect(target_addr).await {
                                            if proxy_enabled {
                                                if let Ok(client_addr) = remote_addr_str.parse::<SocketAddr>() {
                                                    let hdr = format_proxy_v1_header(client_addr, target_addr);
                                                    let _ = target_conn.write_all(hdr.as_bytes()).await;
                                                }
                                            }

                                            let _ = data_exchange(
                                                pool_conn,
                                                target_conn,
                                                read_timeout,
                                                16384,
                                            ).await;
                                        }
                                    }
                                    stats.release_slot(false);
                                }
                            }
                        });
                    }
                }
                "ping" => {
                    let _ = control_loop.send_signal(Signal::pong()).await;
                }
                "pong" => {
                    let rtt = control_loop.last_ping_time().lock().await.elapsed().as_millis();
                    let (tcprx, tcptx, udprx, udptx, tcps, udps) = stats.snapshot();
                    info!(
                        "CHECK_POINT|MODE={}|PING={}ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
                        cfg.run_mode, rtt, pool.active(), tcps, udps, tcprx, tcptx, udprx, udptx
                    );
                }
                "flush" => {
                    pool.flush().await;
                    pool.reset_error();
                    debug!("Tunnel pool flushed: {} active connections", pool.active());
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn perform_handshake(&self) -> io::Result<String> {
        let (tunnel_addr, tunnel_key, data_flow, max_cap, tls_code, pool_type) = {
            let cfg = self.config.read();
            (
                cfg.tunnel_addr.clone(),
                cfg.tunnel_key.clone(),
                cfg.data_flow.clone(),
                cfg.max_pool_capacity,
                cfg.tls_code.clone(),
                cfg.pool_type.clone(),
            )
        };

        let (cert, key) = generate_ephemeral_cert()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let fp = format_cert_fingerprint(&cert);
        info!("TLS code-1: RAM cert prepared with sha256 fingerprint: {}", fp);

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(&tunnel_addr).await?;

        // Accept single handshake HTTP request
        let (tcp_stream, client_addr) = listener.accept().await?;
        let mut tls_stream = acceptor.accept(tcp_stream).await?;

        let mut buf = vec![0u8; 4096];
        let n = tls_stream.read(&mut buf).await?;
        let req_str = String::from_utf8_lossy(&buf[..n]);

        // Validate Authorization header
        let authorized = req_str.lines().any(|line| {
            if line.to_ascii_lowercase().starts_with("authorization: bearer ") {
                let token = line[21..].trim();
                verify_auth_token(token, &tunnel_key)
            } else {
                false
            }
        });

        if !authorized {
            let resp = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unauthorized handshake"));
        }

        info!(
            "Sending tunnel config: FLOW={}|MAX={}|TLS={}|TYPE={}",
            data_flow, max_cap, tls_code, pool_type
        );

        let json_body = format!(
            "{{\"flow\":\"{}\",\"max\":{},\"tls\":\"{}\",\"type\":\"{}\"}}\n",
            data_flow, max_cap, tls_code, pool_type
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        tls_stream.write_all(resp.as_bytes()).await?;
        let _ = tls_stream.shutdown().await;

        let client_ip = client_addr.ip().to_string();
        Ok(client_ip)
    }
}
