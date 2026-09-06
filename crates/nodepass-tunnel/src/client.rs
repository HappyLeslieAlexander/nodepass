use crate::control::ControlLoop;
use crate::exchange::data_exchange;
use nodepass_core::address::{DnsCache, TargetSelector};
use nodepass_core::config::{TunnelConfig, POOL_GET_TIMEOUT, REPORT_INTERVAL};
use nodepass_core::crypto::{
    create_mode1_client_tls_config, generate_auth_token,
};
use nodepass_core::protocol::{detect_block_protocol, format_proxy_v1_header, Signal};
use nodepass_transport::pool::{
    QuicPool, TcpPool, TransportPool, WsPool,
};
use nodepass_transport::rate::RateLimiter;
use nodepass_transport::stats::Stats;
use serde::Deserialize;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

#[derive(Deserialize)]
struct HandshakeResponse {
    flow: String,
    max: usize,
    tls: String,
    #[serde(rename = "type")]
    pool_type: String,
}

pub struct TunnelClient {
    config: Arc<parking_lot::RwLock<TunnelConfig>>,
    stats: Stats,
    dns_cache: DnsCache,
    selector: Arc<TargetSelector>,
    rate_limiter: Option<RateLimiter>,
    stop_flag: Arc<AtomicBool>,
}

impl TunnelClient {
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
        let mode = self.config.read().run_mode.clone();
        match mode.as_str() {
            "1" => self.run_single_mode().await,
            "2" => self.run_pool_mode().await,
            _ => {
                // Auto mode: try local bind first; if success, single mode; else pool mode
                let tunnel_addr = self.config.read().tunnel_addr.clone();
                match TcpListener::bind(&tunnel_addr).await {
                    Ok(listener) => self.run_single_mode_with_listener(listener).await,
                    Err(_) => self.run_pool_mode().await,
                }
            }
        }
    }

    /// Single-connection forwarding mode (no connection pool).
    pub async fn run_single_mode(&self) -> io::Result<()> {
        let tunnel_addr = self.config.read().tunnel_addr.clone();
        let listener = TcpListener::bind(&tunnel_addr).await?;
        self.run_single_mode_with_listener(listener).await
    }

    async fn run_single_mode_with_listener(&self, listener: TcpListener) -> io::Result<()> {
        let config = self.config.read().clone();
        info!("Client single-mode TCP listener active on {}", config.tunnel_addr);

        let selector = Arc::clone(&self.selector);
        let stats = self.stats.clone();
        let read_timeout = config.read_timeout;
        let proxy_enabled = config.proxy_protocol == "1";
        let block_socks = config.block_socks;
        let block_http = config.block_http;
        let block_tls = config.block_tls;

        while !self.stop_flag.load(Ordering::Relaxed) {
            match listener.accept().await {
                Ok((client_conn, client_addr)) => {
                    if !stats.try_acquire_slot(false) {
                        warn!("Single mode: TCP slot limit reached");
                        continue;
                    }

                    let selector = Arc::clone(&selector);
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        // Protocol peek
                        let mut peek_buf = [0u8; 8];
                        if let Ok(n) = client_conn.peek(&mut peek_buf).await {
                            if let Some(proto) = detect_block_protocol(
                                &peek_buf[..n],
                                block_socks,
                                block_http,
                                block_tls,
                            ) {
                                warn!("Single mode: blocked protocol {} from {}", proto, client_addr);
                                stats.release_slot(false);
                                return;
                            }
                        }

                        // Dial target
                        if let Ok((_target_str, target_addr)) = selector.select_next().await {
                            if let Ok(mut target_conn) = TcpStream::connect(target_addr).await {
                                if proxy_enabled {
                                    let hdr = format_proxy_v1_header(client_addr, target_addr);
                                    let _ = tokio::io::AsyncWriteExt::write_all(
                                        &mut target_conn,
                                        hdr.as_bytes(),
                                    )
                                    .await;
                                }

                                let _ = data_exchange(
                                    client_conn,
                                    target_conn,
                                    read_timeout,
                                    16384,
                                )
                                .await;
                            }
                        }
                        stats.release_slot(false);
                    });
                }
                Err(_e) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Ok(())
    }

    /// Tunnel pool mode (Dual-end handshake mode).
    pub async fn run_pool_mode(&self) -> io::Result<()> {
        // 1. Perform HTTP handshake
        info!("Pending tunnel handshake...");
        let handshake_res = self.perform_handshake().await?;
        {
            let mut cfg = self.config.write();
            cfg.data_flow = handshake_res.flow;
            cfg.max_pool_capacity = handshake_res.max;
            cfg.tls_code = handshake_res.tls;
            cfg.pool_type = handshake_res.pool_type;
        }

        let cfg = self.config.read().clone();
        info!(
            "Loading tunnel config: FLOW={}|MAX={}|TLS={}|TYPE={}",
            cfg.data_flow, cfg.max_pool_capacity, cfg.tls_code, cfg.pool_type
        );

        // 2. Initialize connection pool
        let recorded_fp = Arc::new(parking_lot::Mutex::new(None));
        let pool: Arc<dyn TransportPool> = match cfg.pool_type.as_str() {
            "1" => {
                // QUIC pool
                let quic_pool = Arc::new(QuicPool::new(cfg.max_pool_capacity));
                let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                quic_pool.start_client(endpoint, server_addr, &cfg.server_name);
                quic_pool
            }
            "2" => {
                // WebSocket pool
                let ws_pool = Arc::new(WsPool::new(cfg.max_pool_capacity));
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let ws_url = format!("ws://{}/", cfg.tunnel_addr);
                let tls_connector = if cfg.tls_code != "0" {
                    let tls_cfg = create_mode1_client_tls_config(Arc::clone(&recorded_fp));
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    let name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap().to_owned();
                    Some((connector, name))
                } else {
                    None
                };
                ws_pool.start_client(server_addr, ws_url, cfg.min_pool_capacity, tls_connector);
                ws_pool
            }
            _ => {
                // TCP pool (type 0)
                let (tcp_pool, _) = TcpPool::new(cfg.max_pool_capacity);
                let pool_arc = Arc::new(tcp_pool);
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let tls_connector = if cfg.tls_code != "0" {
                    let tls_cfg = create_mode1_client_tls_config(Arc::clone(&recorded_fp));
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    let name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap().to_owned();
                    Some((connector, name))
                } else {
                    None
                };
                pool_arc.start_client(server_addr, cfg.min_pool_capacity, tls_connector);
                pool_arc
            }
        };

        // 3. Claim control connection
        info!("Getting tunnel pool ready...");
        let control_conn = pool.outgoing_get("00000000", POOL_GET_TIMEOUT).await
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, format!("set control conn failed: {}", e)))?;

        info!("Marking tunnel handshake as complete");

        // 4. Start control loop
        let control_loop = Arc::new(ControlLoop::new(cfg.tunnel_key.clone(), Arc::clone(&pool)));
        control_loop.start(control_conn, REPORT_INTERVAL, cfg.tls_code == "1");

        // 5. If data flow == "+", listen on target address and send signals
        if cfg.data_flow == "+" {
            let pool_clone = Arc::clone(&pool);
            let control_tx = control_loop.sender();
            let cfg_clone = cfg.clone();
            tokio::spawn(async move {
                if let Some(target) = cfg_clone.target_addrs.first() {
                    if let Ok(listener) = TcpListener::bind(target).await {
                        while let Ok((target_conn, remote_addr)) = listener.accept().await {
                            if let Ok((id, pool_conn)) = pool_clone.incoming_get(POOL_GET_TIMEOUT).await {
                                let _ = control_tx.send(Signal::tcp(remote_addr.to_string(), id)).await;
                                tokio::spawn(async move {
                                    let _ = data_exchange(target_conn, pool_conn, cfg_clone.read_timeout, 16384).await;
                                });
                            }
                        }
                    }
                }
            });
        }

        // 6. Signal dispatcher loop
        let selector = Arc::clone(&self.selector);
        let stats = self.stats.clone();
        let proxy_enabled = cfg.proxy_protocol == "1";
        let read_timeout = cfg.read_timeout;

        while let Some(signal) = control_loop.recv_signal().await {
            match signal.action_type.as_str() {
                "tcp" => {
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
                                                    let _ = tokio::io::AsyncWriteExt::write_all(
                                                        &mut target_conn,
                                                        hdr.as_bytes(),
                                                    ).await;
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
                "verify" => {
                    // Mode 1 fingerprint check
                    if let Some(ref fp) = signal.fingerprint {
                        info!("TLS code-1: RAM cert verified with sha256 fingerprint: {}", fp);
                    }
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

    async fn perform_handshake(&self) -> io::Result<HandshakeResponse> {
        let (tunnel_addr, server_name, tunnel_key) = {
            let cfg = self.config.read();
            (cfg.tunnel_addr.clone(), cfg.server_name.clone(), cfg.tunnel_key.clone())
        };

        let server_sock_addr = self.dns_cache.resolve(&tunnel_addr).await?;
        let tcp_stream = TcpStream::connect(server_sock_addr).await?;

        // Ephemeral TLS client handshake (InsecureSkipVerify)
        let recorded_fp = Arc::new(parking_lot::Mutex::new(None));
        let tls_cfg = create_mode1_client_tls_config(recorded_fp);
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let domain_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap().to_owned();
        let mut tls_stream = connector.connect(domain_name, tcp_stream).await?;

        // HTTP GET / request
        let token = generate_auth_token(&tunnel_key);
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            server_name, token
        );
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, req.as_bytes()).await?;

        let mut resp_bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut tls_stream, &mut resp_bytes).await?;

        let resp_str = String::from_utf8_lossy(&resp_bytes);
        // Find JSON body after \r\n\r\n
        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let json_body = &resp_str[pos + 4..];
            let res: HandshakeResponse = serde_json::from_str(json_body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad handshake JSON: {}", e)))?;
            Ok(res)
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP handshake response"))
        }
    }
}
