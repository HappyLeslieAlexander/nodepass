use crate::control::ControlLoop;
use crate::exchange::data_exchange_with_stats;
use crate::udp_session::UdpSessionManager;
use dashmap::DashMap;
use nodepass_core::address::{DnsCache, TargetSelector};
use nodepass_core::config::{
    TunnelConfig, POOL_GET_TIMEOUT, REPORT_INTERVAL, UDP_READ_TIMEOUT,
};
use nodepass_core::crypto::{
    constant_time_eq, create_mode1_client_tls_config, create_mode2_client_tls_config,
    generate_auth_token,
};
use nodepass_core::protocol::{detect_block_protocol, format_proxy_v1_header, Signal};
use nodepass_transport::framed::{read_udp_frame, write_udp_frame};
use nodepass_transport::pool::{
    H2Pool, QuicPool, TcpPool, TransportPool, WsPool,
};
use nodepass_transport::rate::RateLimiter;
use nodepass_transport::stats::Stats;
use serde::Deserialize;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let slot_limit = config.slot_limit.max(1);
        Self {
            config: Arc::new(parking_lot::RwLock::new(config)),
            stats: Stats::new(slot_limit),
            dns_cache,
            selector,
            rate_limiter,
            stop_flag: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    /// Auto-restart supervisor loop with SERVICE_COOLDOWN delay (H-1).
    pub async fn run(&self) -> io::Result<()> {
        let mut shutdown_rx = self.shutdown_rx.clone();
        while !self.stop_flag.load(Ordering::Acquire) {
            if let Err(e) = self.start().await {
                if self.stop_flag.load(Ordering::Acquire) || *shutdown_rx.borrow() {
                    break;
                }
                let cooldown = nodepass_core::config::service_cooldown();
                warn!("Tunnel client error: {}. Restarting in {:?}...", e, cooldown);
                tokio::select! {
                    _ = tokio::time::sleep(cooldown) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            } else {
                if self.stop_flag.load(Ordering::Acquire) || *shutdown_rx.borrow() {
                    break;
                }
                let cooldown = nodepass_core::config::service_cooldown();
                warn!("Tunnel client finished unexpectedly. Restarting in {:?}...", cooldown);
                tokio::select! {
                    _ = tokio::time::sleep(cooldown) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn start(&self) -> io::Result<()> {
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
        let rate_limiter = self.rate_limiter.clone();

        // Single mode UDP support
        if !config.disable_udp {
            let tunnel_addr = config.tunnel_addr.clone();
            let selector_udp = Arc::clone(&self.selector);
            let stats_udp = self.stats.clone();
            let stop_flag_udp = Arc::clone(&self.stop_flag);
            let rate_limiter_udp = self.rate_limiter.clone();

            tokio::spawn(async move {
                if let Ok(udp_sock) = UdpSocket::bind(&tunnel_addr).await {
                    let udp_sock = Arc::new(udp_sock);
                    let session_map: Arc<DashMap<SocketAddr, Arc<UdpSocket>>> =
                        Arc::new(DashMap::new());

                    let mut buf = [0u8; 65535];
                    while !stop_flag_udp.load(Ordering::Relaxed) {
                        match udp_sock.recv_from(&mut buf).await {
                            Ok((n, client_addr)) => {
                                if let Some(target_sock) = session_map.get(&client_addr) {
                                    stats_udp.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                                    if let Some(ref r) = rate_limiter_udp {
                                        r.wait_read(n).await;
                                    }
                                    let _ = target_sock.send(&buf[..n]).await;
                                } else {
                                    if !stats_udp.try_acquire_slot(true) {
                                        continue;
                                    }
                                    if let Ok((_, target_addr)) = selector_udp.select_next().await {
                                        if let Ok(target_sock) = UdpSocket::bind("0.0.0.0:0").await {
                                            if target_sock.connect(target_addr).await.is_ok() {
                                                let target_sock = Arc::new(target_sock);
                                                session_map.insert(client_addr, Arc::clone(&target_sock));

                                                stats_udp.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                                                if let Some(ref r) = rate_limiter_udp {
                                                    r.wait_read(n).await;
                                                }
                                                let _ = target_sock.send(&buf[..n]).await;

                                                let udp_sock_clone = Arc::clone(&udp_sock);
                                                let session_map_clone = Arc::clone(&session_map);
                                                let target_sock_clone = Arc::clone(&target_sock);
                                                let stats_clone = stats_udp.clone();
                                                let rate_clone = rate_limiter_udp.clone();

                                                tokio::spawn(async move {
                                                    let mut resp_buf = [0u8; 65535];
                                                    loop {
                                                        match tokio::time::timeout(
                                                            UDP_READ_TIMEOUT,
                                                            target_sock_clone.recv(&mut resp_buf),
                                                        ).await {
                                                            Ok(Ok(m)) if m > 0 => {
                                                                stats_clone.udp_tx.fetch_add(m as u64, Ordering::Relaxed);
                                                                if let Some(ref r) = rate_clone {
                                                                    r.wait_write(m).await;
                                                                }
                                                                let _ = udp_sock_clone.send_to(&resp_buf[..m], client_addr).await;
                                                            }
                                                            _ => break,
                                                        }
                                                    }
                                                    session_map_clone.remove(&client_addr);
                                                    stats_clone.release_slot(true);
                                                });
                                            } else {
                                                stats_udp.release_slot(true);
                                            }
                                        } else {
                                            stats_udp.release_slot(true);
                                        }
                                    } else {
                                        stats_udp.release_slot(true);
                                    }
                                }
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            });
        }

        let mut shutdown_rx = self.shutdown_rx.clone();
        while !self.stop_flag.load(Ordering::Relaxed) {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((client_conn, client_addr)) => {
                            let _ = nodepass_transport::stream::configure_tcp_socket(&client_conn);
                            if !stats.try_acquire_slot(false) {
                                warn!("Single mode: TCP slot limit reached");
                                continue;
                            }

                            let selector = Arc::clone(&selector);
                            let stats = stats.clone();
                            let rate_limiter = rate_limiter.clone();
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
                                        let _ = nodepass_transport::stream::configure_tcp_socket(&target_conn);
                                        if proxy_enabled {
                                            let hdr = format_proxy_v1_header(client_addr, target_addr);
                                            let _ = tokio::io::AsyncWriteExt::write_all(
                                                &mut target_conn,
                                                hdr.as_bytes(),
                                            )
                                            .await;
                                        }

                                        let _ = data_exchange_with_stats(
                                            client_conn,
                                            target_conn,
                                            read_timeout,
                                            16384,
                                            Some(stats.tcp_rx.clone()),
                                            Some(stats.tcp_tx.clone()),
                                            rate_limiter,
                                        )
                                        .await;
                                    }
                                }
                                stats.release_slot(false);
                            });
                        }
                        Err(e) => {
                            if nodepass_transport::stream::is_transient_error(&e) {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            } else {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
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
        let is_verified = Arc::new(AtomicBool::new(cfg.tls_code != "1"));
        let make_client_tls_config = |alpn: Option<Vec<Vec<u8>>>| -> (rustls::ClientConfig, rustls::pki_types::ServerName<'static>) {
            let mut tls_cfg = if cfg.tls_code == "2" {
                create_mode2_client_tls_config(cfg.crt_path.as_deref())
                    .unwrap_or_else(|_| create_mode1_client_tls_config(Arc::clone(&recorded_fp)))
            } else {
                create_mode1_client_tls_config(Arc::clone(&recorded_fp))
            };
            if let Some(alpns) = alpn {
                tls_cfg.alpn_protocols = alpns;
            }
            let sni_str = if !cfg.server_name.is_empty() {
                cfg.server_name.clone()
            } else {
                "localhost".to_string()
            };
            let domain_name = rustls::pki_types::ServerName::try_from(sni_str)
                .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap())
                .to_owned();
            (tls_cfg, domain_name)
        };

        let pool: Arc<dyn TransportPool> = match cfg.pool_type.as_str() {
            "1" => {
                // QUIC pool
                let quic_pool = Arc::new(QuicPool::new(cfg.max_pool_capacity));
                let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
                let (client_tls_cfg, _domain_name) = make_client_tls_config(Some(vec![b"np-quic".to_vec()]));
                let quic_client_config = quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_cfg)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
                ));
                endpoint.set_default_client_config(quic_client_config);
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let sni = if !cfg.server_name.is_empty() {
                    cfg.server_name.as_str()
                } else {
                    "localhost"
                };
                quic_pool.start_client(endpoint, server_addr, sni);
                quic_pool
            }
            "2" => {
                // WebSocket pool
                let ws_pool = Arc::new(WsPool::new(cfg.max_pool_capacity));
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let ws_url = format!("ws://{}/", cfg.tunnel_addr);
                let tls_connector = if cfg.tls_code != "0" {
                    let (tls_cfg, domain_name) = make_client_tls_config(None);
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    Some((connector, domain_name))
                } else {
                    None
                };
                ws_pool.start_client(server_addr, ws_url, cfg.min_pool_capacity, tls_connector);
                ws_pool
            }
            "3" => {
                // HTTP/2 pool
                let h2_pool = Arc::new(H2Pool::new(cfg.max_pool_capacity));
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let tcp_stream = TcpStream::connect(server_addr).await?;
                let _ = nodepass_transport::stream::configure_tcp_socket(&tcp_stream);
                let h2_pool_clone = Arc::clone(&h2_pool);
                let tls_connector = if cfg.tls_code != "0" {
                    let (tls_cfg, domain_name) = make_client_tls_config(Some(vec![b"h2".to_vec()]));
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    Some((connector, domain_name))
                } else {
                    None
                };

                if let Some((connector, name)) = tls_connector {
                    let tls_stream = connector.connect(name, tcp_stream).await?;
                    h2_pool_clone.start_client(tls_stream, cfg.min_pool_capacity);
                } else {
                    h2_pool_clone.start_client(tcp_stream, cfg.min_pool_capacity);
                }
                h2_pool
            }
            _ => {
                // TCP pool (type 0)
                let (tcp_pool, _) = TcpPool::new(cfg.max_pool_capacity);
                let pool_arc = Arc::new(tcp_pool);
                let server_addr = self.dns_cache.resolve(&cfg.tunnel_addr).await?;
                let tls_connector = if cfg.tls_code != "0" {
                    let (tls_cfg, domain_name) = make_client_tls_config(None);
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    Some((connector, domain_name))
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
            let stats_clone = self.stats.clone();
            let rate_limiter_clone = self.rate_limiter.clone();
            let is_verified_tcp = Arc::clone(&is_verified);

            tokio::spawn(async move {
                if let Some(target) = cfg_clone.target_addrs.first() {
                    if let Ok(listener) = TcpListener::bind(target).await {
                        while let Ok((target_conn, remote_addr)) = listener.accept().await {
                            let _ = nodepass_transport::stream::configure_tcp_socket(&target_conn);
                            if !is_verified_tcp.load(Ordering::SeqCst) {
                                warn!("Dropping TCP connection: TLS Mode 1 not yet verified");
                                drop(target_conn);
                                continue;
                            }
                            if !stats_clone.try_acquire_slot(false) {
                                warn!("TCP slot limit reached");
                                continue;
                            }
                            if let Ok((id, pool_conn)) = pool_clone.incoming_get(POOL_GET_TIMEOUT).await {
                                let _ = control_tx.send(Signal::tcp(remote_addr.to_string(), id)).await;
                                let stats = stats_clone.clone();
                                let rate_limit = rate_limiter_clone.clone();
                                tokio::spawn(async move {
                                    let _ = data_exchange_with_stats(
                                        target_conn,
                                        pool_conn,
                                        cfg_clone.read_timeout,
                                        16384,
                                        Some(stats.tcp_rx.clone()),
                                        Some(stats.tcp_tx.clone()),
                                        rate_limit,
                                    ).await;
                                    stats.release_slot(false);
                                });
                            } else {
                                stats_clone.release_slot(false);
                            }
                        }
                    }
                }
            });

            // Pooled mode UDP listener when data_flow == "+"
            if !cfg.disable_udp {
                let pool_udp = Arc::clone(&pool);
                let control_tx_udp = control_loop.sender();
                let cfg_udp = cfg.clone();
                let stats_udp = self.stats.clone();
                let is_verified_udp = Arc::clone(&is_verified);

                tokio::spawn(async move {
                    if let Some(target) = cfg_udp.target_addrs.first() {
                        if let Ok(udp_sock) = UdpSocket::bind(target).await {
                            let udp_sock = Arc::new(udp_sock);
                            let sessions = UdpSessionManager::new();

                            let mut buf = [0u8; 65535];
                            while let Ok((n, client_addr)) = udp_sock.recv_from(&mut buf).await {
                                if !is_verified_udp.load(Ordering::SeqCst) {
                                    continue;
                                }
                                if let Some(session_tx) = sessions.get_active(&client_addr) {
                                    stats_udp.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                                    let _ = session_tx.try_send(buf[..n].to_vec());
                                } else {
                                    if !stats_udp.try_acquire_slot(true) {
                                        continue;
                                    }
                                    if let Ok((id, pool_conn)) = pool_udp.incoming_get(POOL_GET_TIMEOUT).await {
                                        let _ = control_tx_udp.send(Signal::udp(client_addr.to_string(), id)).await;
                                        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                                        sessions.insert(client_addr, tx.clone());

                                        stats_udp.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                                        let _ = tx.try_send(buf[..n].to_vec());

                                        let udp_sock_clone = Arc::clone(&udp_sock);
                                        let sessions_clone = sessions.clone();
                                        let stats_clone = stats_udp.clone();
                                        let stats_reader = stats_clone.clone();

                                        tokio::spawn(async move {
                                            let (mut r_stream, mut w_stream) = tokio::io::split(pool_conn);
                                            let last_active = Arc::new(parking_lot::Mutex::new(std::time::Instant::now()));
                                            let last_active_writer = Arc::clone(&last_active);
                                            let last_active_reader = Arc::clone(&last_active);

                                            let writer_task = async move {
                                                while let Some(data) = rx.recv().await {
                                                    *last_active_writer.lock() = std::time::Instant::now();
                                                    if write_udp_frame(&mut w_stream, &data).await.is_err() {
                                                        break;
                                                    }
                                                }
                                            };

                                            let reader_task = async move {
                                                let mut resp_buf = [0u8; 65535];
                                                loop {
                                                    match read_udp_frame(&mut r_stream, &mut resp_buf, UDP_READ_TIMEOUT).await {
                                                        Ok(m) if m > 0 => {
                                                            *last_active_reader.lock() = std::time::Instant::now();
                                                            stats_reader.udp_tx.fetch_add(m as u64, Ordering::Relaxed);
                                                            let _ = udp_sock_clone.send_to(&resp_buf[..m], client_addr).await;
                                                        }
                                                        Ok(_) => break,
                                                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                                            if last_active_reader.lock().elapsed() >= UDP_READ_TIMEOUT {
                                                                break;
                                                            }
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                            };

                                            tokio::select! {
                                                _ = writer_task => {},
                                                _ = reader_task => {},
                                            }
                                            sessions_clone.remove(&client_addr);
                                            stats_clone.release_slot(true);
                                        });
                                    } else {
                                        stats_udp.release_slot(true);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        // 6. Signal dispatcher loop
        let selector = Arc::clone(&self.selector);
        let stats = self.stats.clone();
        let proxy_enabled = cfg.proxy_protocol == "1";
        let read_timeout = cfg.read_timeout;
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            let signal = tokio::select! {
                res = control_loop.recv_signal() => {
                    match res {
                        Some(s) => s,
                        None => break,
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Tunnel client shutdown triggered");
                        control_loop.stop();
                        break;
                    }
                    continue;
                }
            };
            match signal.action_type.as_str() {
                "tcp" => {
                    if !is_verified.load(Ordering::SeqCst) {
                        warn!("Dropping incoming TCP signal: TLS Mode 1 not yet verified");
                        continue;
                    }
                    if let Some(id) = signal.pool_conn_id {
                        let pool_clone = Arc::clone(&pool);
                        let selector = Arc::clone(&selector);
                        let stats = stats.clone();
                        let rate_limiter = rate_limiter.clone();
                        let remote_addr_str = signal.remote_addr.unwrap_or_default();

                        tokio::spawn(async move {
                            if let Ok(pool_conn) = pool_clone.outgoing_get(&id, POOL_GET_TIMEOUT).await {
                                if stats.try_acquire_slot(false) {
                                    if let Ok((_, target_addr)) = selector.select_next().await {
                                        if let Ok(mut target_conn) = TcpStream::connect(target_addr).await {
                                            let _ = nodepass_transport::stream::configure_tcp_socket(&target_conn);
                                            if proxy_enabled {
                                                if let Ok(client_addr) = remote_addr_str.parse::<SocketAddr>() {
                                                    let hdr = format_proxy_v1_header(client_addr, target_addr);
                                                    let _ = tokio::io::AsyncWriteExt::write_all(
                                                        &mut target_conn,
                                                        hdr.as_bytes(),
                                                    ).await;
                                                }
                                            }

                                            let _ = data_exchange_with_stats(
                                                pool_conn,
                                                target_conn,
                                                read_timeout,
                                                16384,
                                                Some(stats.tcp_rx.clone()),
                                                Some(stats.tcp_tx.clone()),
                                                rate_limiter,
                                            ).await;
                                        }
                                    }
                                    stats.release_slot(false);
                                }
                            }
                        });
                    }
                }
                "udp" => {
                    if !is_verified.load(Ordering::SeqCst) {
                        warn!("Dropping incoming UDP signal: TLS Mode 1 not yet verified");
                        continue;
                    }
                    // Pooled mode UDP: when data_flow == "-", server received UDP datagram and requested client to dial target UDP
                    if let Some(id) = signal.pool_conn_id {
                        let pool_clone = Arc::clone(&pool);
                        let selector = Arc::clone(&selector);
                        let stats = stats.clone();

                        tokio::spawn(async move {
                            if let Ok(pool_conn) = pool_clone.outgoing_get(&id, POOL_GET_TIMEOUT).await {
                                if stats.try_acquire_slot(true) {
                                    if let Ok((_, target_addr)) = selector.select_next().await {
                                        if let Ok(target_sock) = UdpSocket::bind("0.0.0.0:0").await {
                                            if target_sock.connect(target_addr).await.is_ok() {
                                                let target_sock = Arc::new(target_sock);
                                                let target_sock_read = Arc::clone(&target_sock);
                                                let stats_t = stats.clone();

                                                let (mut r_stream, mut w_stream) = tokio::io::split(pool_conn);
                                                let last_active = Arc::new(parking_lot::Mutex::new(std::time::Instant::now()));
                                                let last_active_task1 = Arc::clone(&last_active);
                                                let last_active_task2 = Arc::clone(&last_active);

                                                let task1 = async move {
                                                    let mut buf = [0u8; 65535];
                                                    loop {
                                                        match read_udp_frame(&mut r_stream, &mut buf, UDP_READ_TIMEOUT).await {
                                                            Ok(n) if n > 0 => {
                                                                *last_active_task1.lock() = std::time::Instant::now();
                                                                stats_t.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                                                                let _ = target_sock.send(&buf[..n]).await;
                                                            }
                                                            Ok(_) => break,
                                                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                                                if last_active_task1.lock().elapsed() >= UDP_READ_TIMEOUT {
                                                                    break;
                                                                }
                                                            }
                                                            Err(_) => break,
                                                        }
                                                    }
                                                };

                                                let task2 = async move {
                                                    let mut buf = [0u8; 65535];
                                                    loop {
                                                        match tokio::time::timeout(UDP_READ_TIMEOUT, target_sock_read.recv(&mut buf)).await {
                                                            Ok(Ok(n)) if n > 0 => {
                                                                *last_active_task2.lock() = std::time::Instant::now();
                                                                stats_t.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                                                                if write_udp_frame(&mut w_stream, &buf[..n]).await.is_err() {
                                                                    break;
                                                                }
                                                            }
                                                            Ok(Ok(_)) => break,
                                                            Ok(Err(_)) => break,
                                                            Err(_) => {
                                                                if last_active_task2.lock().elapsed() >= UDP_READ_TIMEOUT {
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                };

                                                tokio::select! {
                                                    _ = task1 => {}
                                                    _ = task2 => {}
                                                }
                                            }
                                        }
                                    }
                                    stats.release_slot(true);
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
                    // TLS Mode 1 fingerprint check: compare received fingerprint with recorded cert
                    match signal.fingerprint.as_deref() {
                        Some(fp) => {
                            let recorded = recorded_fp.lock().clone();
                            match recorded.as_deref() {
                                Some(expected_fp) => {
                                    if !constant_time_eq(fp.as_bytes(), expected_fp.as_bytes()) {
                                        warn!("TLS code-1: fingerprint mismatch: expected {} but got {}", expected_fp, fp);
                                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "TLS fingerprint mismatch"));
                                    }
                                    is_verified.store(true, Ordering::SeqCst);
                                    let _ = control_loop.send_signal(Signal::verify("00000000", fp.to_string())).await;
                                    info!("TLS code-1: RAM cert verified with sha256 fingerprint: {}", fp);
                                }
                                None => {
                                    warn!("TLS code-1: verify signal received but no certificate fingerprint was recorded");
                                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "No TLS fingerprint recorded"));
                                }
                            }
                        }
                        None => {
                            warn!("TLS code-1: verify signal missing fingerprint");
                            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Missing TLS fingerprint in verify signal"));
                        }
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

        if !*shutdown_rx.borrow() && !self.is_stopped() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tunnel control connection lost",
            ));
        }

        Ok(())
    }

    async fn perform_handshake(&self) -> io::Result<HandshakeResponse> {
        let (tunnel_addr, server_name, tunnel_key, crt_path) = {
            let cfg = self.config.read();
            (
                cfg.tunnel_addr.clone(),
                cfg.server_name.clone(),
                cfg.tunnel_key.clone(),
                cfg.crt_path.clone(),
            )
        };

        let server_sock_addr = self.dns_cache.resolve(&tunnel_addr).await?;
        let tcp_stream = TcpStream::connect(server_sock_addr).await?;
        let _ = nodepass_transport::stream::configure_tcp_socket(&tcp_stream);

        // Ephemeral TLS client handshake
        let recorded_fp = Arc::new(parking_lot::Mutex::new(None));
        let tls_cfg = create_mode2_client_tls_config(crt_path.as_deref())
            .unwrap_or_else(|_| create_mode1_client_tls_config(recorded_fp));
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let sni_str = if !server_name.is_empty() {
            server_name.clone()
        } else {
            "localhost".to_string()
        };
        let domain_name = rustls::pki_types::ServerName::try_from(sni_str)
            .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap())
            .to_owned();
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
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("handshake failed: {}", resp_str.lines().next().unwrap_or("unknown error")),
            ));
        }

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
