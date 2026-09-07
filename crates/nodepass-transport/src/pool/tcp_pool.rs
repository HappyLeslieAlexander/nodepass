use super::{PoolError, TransportPool};
use crate::stream::{box_stream, BoxedStream};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct TcpPool {
    max_capacity: usize,
    control_stream: Arc<Mutex<Option<BoxedStream>>>,
    control_notify: Arc<Notify>,
    idle_tx: mpsc::Sender<BoxedStream>,
    idle_rx: Arc<Mutex<mpsc::Receiver<BoxedStream>>>,
    active_count: Arc<AtomicUsize>,
    error_count: Arc<AtomicUsize>,
    is_ready: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
}

impl TcpPool {
    pub fn new(max_capacity: usize) -> (Self, mpsc::Sender<BoxedStream>) {
        let (tx, rx) = mpsc::channel(max_capacity.max(16));
        let pool = Self {
            max_capacity,
            control_stream: Arc::new(Mutex::new(None)),
            control_notify: Arc::new(Notify::new()),
            idle_tx: tx.clone(),
            idle_rx: Arc::new(Mutex::new(rx)),
            active_count: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
            is_ready: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        };
        (pool, tx)
    }

    /// Spawns background worker for server mode accepting TCP connections.
    pub fn start_server(&self, listener: TcpListener, tls_acceptor: Option<TlsAcceptor>) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let idle_tx = self.idle_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            let mut is_first = true;
            while !stop_flag.load(Ordering::Acquire) {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let _ = crate::stream::configure_tcp_socket(&stream);
                        let boxed: BoxedStream = if let Some(ref acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => box_stream(tls_stream),
                                Err(_) => continue,
                            }
                        } else {
                            box_stream(stream)
                        };

                        if is_first {
                            is_first = false;
                            *control_stream.lock().await = Some(boxed);
                            is_ready.store(true, Ordering::Release);
                            control_notify.notify_waiters();
                        } else {
                            active_count.fetch_add(1, Ordering::Release);
                            let _ = idle_tx.send(boxed).await;
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }

    /// Spawns background worker for client mode maintaining pool connections.
    pub fn start_client(
        &self,
        tunnel_addr: SocketAddr,
        min_capacity: usize,
        tls_connector: Option<(TlsConnector, rustls::pki_types::ServerName<'static>)>,
    ) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let idle_tx = self.idle_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            let min_interval = nodepass_core::config::min_pool_interval();
            let max_interval = nodepass_core::config::max_pool_interval();

            // First: establish the control connection with progressive backoff on failure
            let mut ctrl_interval = min_interval;
            while !stop_flag.load(Ordering::Acquire) {
                if let Ok(stream) = TcpStream::connect(tunnel_addr).await {
                    let _ = crate::stream::configure_tcp_socket(&stream);
                    let boxed: BoxedStream = if let Some((ref connector, ref name)) = tls_connector
                    {
                        match connector.connect(name.clone(), stream).await {
                            Ok(tls_stream) => box_stream(tls_stream),
                            Err(_) => {
                                ctrl_interval =
                                    (ctrl_interval + Duration::from_millis(100)).min(max_interval);
                                tokio::time::sleep(ctrl_interval).await;
                                continue;
                            }
                        }
                    } else {
                        box_stream(stream)
                    };

                    *control_stream.lock().await = Some(boxed);
                    is_ready.store(true, Ordering::Release);
                    control_notify.notify_waiters();
                    break;
                }
                ctrl_interval = (ctrl_interval + Duration::from_millis(100)).min(max_interval);
                tokio::time::sleep(ctrl_interval).await;
            }

            // Pool expansion loop with progressive backoff on idle/unreachable (H-5)
            let mut interval = min_interval;
            while !stop_flag.load(Ordering::Acquire) {
                let current = active_count.load(Ordering::Acquire);
                if current < min_capacity {
                    match TcpStream::connect(tunnel_addr).await {
                        Ok(stream) => {
                            let _ = crate::stream::configure_tcp_socket(&stream);
                            let boxed: BoxedStream =
                                if let Some((ref connector, ref name)) = tls_connector {
                                    match connector.connect(name.clone(), stream).await {
                                        Ok(tls_stream) => box_stream(tls_stream),
                                        Err(_) => {
                                            interval = (interval + Duration::from_millis(100))
                                                .min(max_interval);
                                            tokio::time::sleep(interval).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    box_stream(stream)
                                };

                            active_count.fetch_add(1, Ordering::Release);
                            interval = min_interval; // reset interval on successful addition
                            if idle_tx.send(boxed).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            // Unreachable: progressively back off interval toward max_pool_interval
                            interval = (interval + Duration::from_millis(100)).min(max_interval);
                        }
                    }
                } else {
                    // Pool is satisfied (idle): back off gradually
                    interval = (interval + Duration::from_millis(100)).min(max_interval);
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

#[async_trait]
impl TransportPool for TcpPool {
    async fn incoming_get(&self, timeout: Duration) -> Result<(String, BoxedStream), PoolError> {
        let mut rx = self.idle_rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(stream)) => {
                let id = format!("{:08x}", rand::random::<u32>());
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                Ok((id, stream))
            }
            Ok(None) => Err(PoolError::Closed),
            Err(_) => Err(PoolError::Timeout),
        }
    }

    async fn outgoing_get(&self, id: &str, timeout: Duration) -> Result<BoxedStream, PoolError> {
        if id == "00000000" {
            // Wait for control connection
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                {
                    let mut lock = self.control_stream.lock().await;
                    if let Some(stream) = lock.take() {
                        return Ok(stream);
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(PoolError::Timeout);
                }
                let remaining = deadline - tokio::time::Instant::now();
                let _ = tokio::time::timeout(remaining, self.control_notify.notified()).await;
            }
        }

        let mut rx = self.idle_rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(stream)) => {
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                Ok(stream)
            }
            Ok(None) => Err(PoolError::Closed),
            Err(_) => Err(PoolError::Timeout),
        }
    }

    async fn flush(&self) {
        let mut rx = self.idle_rx.lock().await;
        while let Ok(stream) = rx.try_recv() {
            drop(stream);
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn close(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.flush().await;
    }

    fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    fn capacity(&self) -> usize {
        self.max_capacity
    }

    fn add_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    fn reset_error(&self) {
        self.error_count.store(0, Ordering::Relaxed);
    }

    fn error_count(&self) -> usize {
        self.error_count.load(Ordering::Relaxed)
    }
}
