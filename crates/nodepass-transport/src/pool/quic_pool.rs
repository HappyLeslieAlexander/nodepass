use super::{PoolError, TransportPool};
use crate::adapters::QuinnStream;
use crate::stream::{box_stream, BoxedStream};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};

pub const QUIC_ALPN: &[&[u8]] = &[b"np-quic"];

pub struct QuicPool {
    max_capacity: usize,
    control_stream: Arc<Mutex<Option<BoxedStream>>>,
    control_notify: Arc<Notify>,
    quic_conn: Arc<Mutex<Option<quinn::Connection>>>,
    stream_tx: mpsc::Sender<BoxedStream>,
    stream_rx: Arc<Mutex<mpsc::Receiver<BoxedStream>>>,
    active_count: Arc<AtomicUsize>,
    error_count: Arc<AtomicUsize>,
    is_ready: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
}

impl QuicPool {
    pub fn new(max_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(max_capacity.max(16));
        Self {
            max_capacity,
            control_stream: Arc::new(Mutex::new(None)),
            control_notify: Arc::new(Notify::new()),
            quic_conn: Arc::new(Mutex::new(None)),
            stream_tx: tx,
            stream_rx: Arc::new(Mutex::new(rx)),
            active_count: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
            is_ready: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts QUIC pool server listening on the provided Quinn Endpoint.
    pub fn start_server(&self, endpoint: quinn::Endpoint) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let quic_conn = Arc::clone(&self.quic_conn);
        let stream_tx = self.stream_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            while !stop_flag.load(Ordering::Relaxed) {
                if let Some(incoming) = endpoint.accept().await {
                    if let Ok(conn) = incoming.await {
                        *quic_conn.lock().await = Some(conn.clone());

                        // Accept the first bidirectional stream as control
                        if let Ok((send, recv)) = conn.accept_bi().await {
                            let boxed = box_stream(QuinnStream::new(send, recv));
                            *control_stream.lock().await = Some(boxed);
                            is_ready.store(true, Ordering::SeqCst);
                            control_notify.notify_waiters();

                            // Accept remaining streams for data
                            let stream_tx = stream_tx.clone();
                            let active_count = Arc::clone(&active_count);
                            let stop_flag = Arc::clone(&stop_flag);
                            tokio::spawn(async move {
                                while !stop_flag.load(Ordering::Relaxed) {
                                    match conn.accept_bi().await {
                                        Ok((send, recv)) => {
                                            active_count.fetch_add(1, Ordering::Relaxed);
                                            let boxed = box_stream(QuinnStream::new(send, recv));
                                            if stream_tx.send(boxed).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });
    }

    /// Starts QUIC pool client connecting to tunnel_addr via Quinn Endpoint.
    pub fn start_client(
        &self,
        endpoint: quinn::Endpoint,
        server_addr: SocketAddr,
        server_name: &str,
    ) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let quic_conn = Arc::clone(&self.quic_conn);
        let stream_tx = self.stream_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);
        let server_name = server_name.to_string();

        tokio::spawn(async move {
            while !stop_flag.load(Ordering::Relaxed) {
                match endpoint.connect(server_addr, &server_name) {
                    Ok(connecting) => match connecting.await {
                        Ok(conn) => {
                            *quic_conn.lock().await = Some(conn.clone());

                            // Open the first bidirectional stream for control
                            match conn.open_bi().await {
                                Ok((send, recv)) => {
                                    let boxed = box_stream(QuinnStream::new(send, recv));
                                    *control_stream.lock().await = Some(boxed);
                                    is_ready.store(true, Ordering::SeqCst);
                                    control_notify.notify_waiters();

                                    // Accept inbound data streams from server
                                    let stream_tx = stream_tx.clone();
                                    let active_count = Arc::clone(&active_count);
                                    let stop_flag = Arc::clone(&stop_flag);
                                    let conn_clone = conn.clone();
                                    tokio::spawn(async move {
                                        while !stop_flag.load(Ordering::Relaxed) {
                                            match conn_clone.accept_bi().await {
                                                Ok((send, recv)) => {
                                                    active_count.fetch_add(1, Ordering::Relaxed);
                                                    let boxed =
                                                        box_stream(QuinnStream::new(send, recv));
                                                    if stream_tx.send(boxed).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    });
                                    break;
                                }
                                Err(_) => {
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                }
                            }
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    },
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
}

#[async_trait]
impl TransportPool for QuicPool {
    async fn incoming_get(&self, timeout: Duration) -> Result<(String, BoxedStream), PoolError> {
        let conn_opt = self.quic_conn.lock().await.clone();
        if let Some(conn) = conn_opt {
            match tokio::time::timeout(timeout, conn.open_bi()).await {
                Ok(Ok((send, recv))) => {
                    let id = format!("{:08x}", rand::random::<u32>());
                    Ok((id, box_stream(QuinnStream::new(send, recv))))
                }
                Ok(Err(e)) => Err(PoolError::Other(e.to_string())),
                Err(_) => Err(PoolError::Timeout),
            }
        } else {
            // Check pre-buffered queue
            let mut rx = self.stream_rx.lock().await;
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

        let mut rx = self.stream_rx.lock().await;
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
        let mut rx = self.stream_rx.lock().await;
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
