use crate::control::ControlLoop;
use crate::exchange::data_exchange_with_stats;
use crate::udp_session::UdpSessionManager;
use nodepass_core::address::{DnsCache, TargetSelector};
use nodepass_core::config::{
    TunnelConfig, POOL_GET_TIMEOUT, REPORT_INTERVAL, UDP_READ_TIMEOUT,
};
use nodepass_core::crypto::{
    constant_time_eq, format_cert_fingerprint, generate_ephemeral_cert, verify_auth_token,
    verify_pre_auth,
};
use nodepass_core::protocol::{detect_block_protocol, format_proxy_v1_header, Signal};
use nodepass_transport::framed::{read_udp_frame, write_udp_frame};
use nodepass_transport::pool::{
    H2Pool, QuicPool, TcpPool, TransportPool, WsPool,
};
use nodepass_transport::rate::RateLimiter;
use nodepass_transport::stats::Stats;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct TunnelServer {
    config: Arc<parking_lot::RwLock<TunnelConfig>>,
    stats: Stats,
    dns_cache: DnsCache,
    selector: Arc<TargetSelector>,
    rate_limiter: Option<RateLimiter>,
    stop_flag: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        Self {
            config: Arc::new(parking_lot::RwLock::new(config)),
            stats: Stats::new(65536),
            dns_cache,
            selector,
            rate_limiter,
            stop_flag: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn run(&self) -> io::Result<()> {
        // 1. Determine run mode and flow direction
        let (initial_mode, target_to_test) = {
            let cfg = self.config.read();
            (cfg.run_mode.clone(), cfg.target_addrs.first().cloned().unwrap_or_default())
        };

        let (run_mode, data_flow) = match initial_mode.as_str() {
            "1" => ("1".to_string(), "-".to_string()),
            "2" => ("2".to_string(), "+".to_string()),
            _ => {
                if !target_to_test.is_empty() && TcpListener::bind(&target_to_test).await.is_ok() {
                    ("1".to_string(), "-".to_string())
                } else {
                    ("2".to_string(), "+".to_string())
                }
            }
        };

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
                    .map_err(|e| io::Error::other(e.to_string()))?;
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
                    .map_err(|e| io::Error::other(e.to_string()))?;
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
                let stop_flag = Arc::clone(&self.stop_flag);
                tokio::spawn(async move {
                    while !stop_flag.load(Ordering::Relaxed) {
                        if let Ok((tcp_stream, _)) = listener.accept().await {
                            let h2_p = Arc::clone(&h2_pool_clone);
                            if let Some(ref acc) = tls_acc {
                                if let Ok(tls_stream) = acc.accept(tcp_stream).await {
                                    h2_p.start_server(tls_stream);
                                    break;
                                }
                            } else {
                                h2_p.start_server(tcp_stream);
                                break;
                            }
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

        let is_verified = Arc::new(AtomicBool::new(cfg.tls_code != "1"));

        // If TLS code 1, send verify signal with new fingerprint
        if cfg.tls_code == "1" {
            if let Some(ref fp) = new_fingerprint {
                let _ = control_loop.send_signal(Signal::verify("00000000", fp.clone())).await;
            }
        }

        // 7. If data_flow == "-", listen on target address and send signals into tunnel
        if cfg.data_flow == "-" {
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
                            if !is_verified_tcp.load(Ordering::SeqCst) {
                                warn!("Dropping incoming TCP connection: TLS Mode 1 not yet verified");
                                drop(target_conn);
                                continue;
                            }
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
                            let rate_limit = rate_limiter_clone.clone();

                            tokio::spawn(async move {
                                if let Ok((id, pool_conn)) = pool.incoming_get(POOL_GET_TIMEOUT).await {
                                    let _ = control_tx.send(Signal::tcp(remote_addr.to_string(), id)).await;
                                    let _ = data_exchange_with_stats(
                                        target_conn,
                                        pool_conn,
                                        read_timeout,
                                        16384,
                                        Some(stats.tcp_rx.clone()),
                                        Some(stats.tcp_tx.clone()),
                                        rate_limit,
                                    ).await;
                                }
                                stats.release_slot(false);
                            });
                        }
                    }
                }
            });

            // Pooled mode UDP listener when data_flow == "-"
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

        // 8. Signal dispatcher loop
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
                        info!("Tunnel server shutdown triggered");
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
                    // When data_flow is "+", incoming user connections arrive at the client,
                    // which sends a "tcp" signal to the server to forward to target.
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
                                            if proxy_enabled {
                                                if let Ok(client_addr) = remote_addr_str.parse::<SocketAddr>() {
                                                    let hdr = format_proxy_v1_header(client_addr, target_addr);
                                                    let _ = target_conn.write_all(hdr.as_bytes()).await;
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
                    // Pooled mode UDP: when data_flow == "+", client received UDP datagram and requested server to dial target UDP
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
                    // TLS Mode 1 fingerprint check: compare client-sent fingerprint with local cert
                    match signal.fingerprint.as_deref() {
                        Some(fp) => {
                            match new_fingerprint.as_deref() {
                                Some(expected_fp) => {
                                    if !constant_time_eq(fp.as_bytes(), expected_fp.as_bytes()) {
                                        warn!("TLS code-1: fingerprint mismatch: expected {} but got {}", expected_fp, fp);
                                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "TLS fingerprint mismatch"));
                                    }
                                    is_verified.store(true, Ordering::SeqCst);
                                    info!("TLS code-1: RAM cert verified with sha256 fingerprint: {}", fp);
                                }
                                None => {
                                    warn!("TLS code-1: verify signal received but no server certificate was configured");
                                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "No TLS server certificate"));
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
            .map_err(|e| io::Error::other(e.to_string()))?;
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

        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        const MAX_HEADER_SIZE: usize = 65536;
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            if buf.len() >= MAX_HEADER_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP handshake headers exceeded 64KB limit"));
            }
            let n = tls_stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP handshake connection closed prematurely"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let req_str = String::from_utf8_lossy(&buf);

        // Handle CONNECT method pre-auth
        if req_str.starts_with("CONNECT ") {
            let authorized = req_str.lines().any(|line| {
                if line.to_ascii_lowercase().starts_with("proxy-authorization: ") {
                    verify_pre_auth(line[21..].trim(), &tunnel_key)
                } else {
                    false
                }
            });

            if !authorized {
                let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\nConnection: close\r\n\r\n";
                let _ = tls_stream.write_all(resp.as_bytes()).await;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unauthorized CONNECT pre-auth"));
            }

            let resp = "HTTP/1.1 200 Connection established\r\n\r\n";
            tls_stream.write_all(resp.as_bytes()).await?;
            return Ok(client_addr.ip().to_string());
        }

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
