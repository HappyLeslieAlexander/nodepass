use super::{PoolError, TransportPool};
use crate::adapters::WsStream;
use crate::stream::{box_stream, BoxedStream};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct WsPool {
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

impl WsPool {
    pub fn new(max_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(max_capacity.max(16));
        Self {
            max_capacity,
            control_stream: Arc::new(Mutex::new(None)),
            control_notify: Arc::new(Notify::new()),
            idle_tx: tx,
            idle_rx: Arc::new(Mutex::new(rx)),
            active_count: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
            is_ready: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts WebSocket pool server.
    pub fn start_server(&self, listener: TcpListener, tls_acceptor: Option<TlsAcceptor>) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let idle_tx = self.idle_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            let mut is_first = true;
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok((tcp_stream, _)) = listener.accept().await {
                    let tls_opt = tls_acceptor.clone();
                    let control_stream = Arc::clone(&control_stream);
                    let control_notify = Arc::clone(&control_notify);
                    let idle_tx = idle_tx.clone();
                    let active_count = Arc::clone(&active_count);
                    let is_ready = Arc::clone(&is_ready);

                    let was_first = is_first;
                    is_first = false;

                    tokio::spawn(async move {
                        let ws_stream = if let Some(ref acceptor) = tls_opt {
                            match acceptor.accept(tcp_stream).await {
                                Ok(tls_stream) => match tokio_tungstenite::accept_async(tls_stream).await {
                                    Ok(ws) => box_stream(WsStream::new(ws)),
                                    Err(_) => return,
                                },
                                Err(_) => return,
                            }
                        } else {
                            match tokio_tungstenite::accept_async(tcp_stream).await {
                                Ok(ws) => box_stream(WsStream::new(ws)),
                                Err(_) => return,
                            }
                        };

                        if was_first {
                            *control_stream.lock().await = Some(ws_stream);
                            is_ready.store(true, Ordering::SeqCst);
                            control_notify.notify_waiters();
                        } else {
                            active_count.fetch_add(1, Ordering::Relaxed);
                            let _ = idle_tx.send(ws_stream).await;
                        }
                    });
                }
            }
        });
    }

    /// Starts WebSocket pool client.
    pub fn start_client(
        &self,
        tunnel_addr: SocketAddr,
        ws_url: String,
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
            // First: connect control stream
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok(tcp_stream) = TcpStream::connect(tunnel_addr).await {
                    let boxed_tcp: BoxedStream = if let Some((ref connector, ref name)) = tls_connector {
                        match connector.connect(name.clone(), tcp_stream).await {
                            Ok(tls_stream) => box_stream(tls_stream),
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                    } else {
                        box_stream(tcp_stream)
                    };

                    if let Ok((ws, _)) = tokio_tungstenite::client_async(&ws_url, boxed_tcp).await {
                        *control_stream.lock().await = Some(box_stream(WsStream::new(ws)));
                        is_ready.store(true, Ordering::SeqCst);
                        control_notify.notify_waiters();
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Pool expansion loop
            while !stop_flag.load(Ordering::Relaxed) {
                let current = active_count.load(Ordering::Relaxed);
                if current < min_capacity {
                    if let Ok(tcp_stream) = TcpStream::connect(tunnel_addr).await {
                        let boxed_tcp: BoxedStream = if let Some((ref connector, ref name)) = tls_connector {
                            match connector.connect(name.clone(), tcp_stream).await {
                                Ok(tls_stream) => box_stream(tls_stream),
                                Err(_) => {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    continue;
                                }
                            }
                        } else {
                            box_stream(tcp_stream)
                        };

                        if let Ok((ws, _)) = tokio_tungstenite::client_async(&ws_url, boxed_tcp).await {
                            active_count.fetch_add(1, Ordering::Relaxed);
                            if idle_tx.send(box_stream(WsStream::new(ws))).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
}

#[async_trait]
impl TransportPool for WsPool {
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
