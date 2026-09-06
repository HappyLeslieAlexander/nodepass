use super::{PoolError, TransportPool};
use crate::adapters::H2Stream;
use crate::stream::{box_stream, BoxedStream};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};

pub const H2_ALPN: &[&[u8]] = &[b"h2"];

pub struct H2Pool {
    max_capacity: usize,
    control_stream: Arc<Mutex<Option<BoxedStream>>>,
    control_notify: Arc<Notify>,
    send_request: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
    stream_tx: mpsc::Sender<BoxedStream>,
    stream_rx: Arc<Mutex<mpsc::Receiver<BoxedStream>>>,
    active_count: Arc<AtomicUsize>,
    error_count: Arc<AtomicUsize>,
    is_ready: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
}

impl H2Pool {
    pub fn new(max_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(max_capacity.max(16));
        Self {
            max_capacity,
            control_stream: Arc::new(Mutex::new(None)),
            control_notify: Arc::new(Notify::new()),
            send_request: Arc::new(Mutex::new(None)),
            stream_tx: tx,
            stream_rx: Arc::new(Mutex::new(rx)),
            active_count: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
            is_ready: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts H2 pool server on an underlying stream.
    pub fn start_server<S: crate::stream::AsyncStream>(&self, stream: S) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let stream_tx = self.stream_tx.clone();
        let active_count = Arc::clone(&self.active_count);
        let is_ready = Arc::clone(&self.is_ready);
        let stop_flag = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            let mut server = match h2::server::handshake(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };

            let mut is_first = true;
            while !stop_flag.load(Ordering::Relaxed) {
                match server.accept().await {
                    Some(Ok((req, mut respond))) => {
                        let res = Response::builder().status(200).body(()).unwrap();
                        let send = match respond.send_response(res, false) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let recv = req.into_body();
                        let boxed = box_stream(H2Stream::new(send, recv));

                        if is_first {
                            is_first = false;
                            *control_stream.lock().await = Some(boxed);
                            is_ready.store(true, Ordering::SeqCst);
                            control_notify.notify_waiters();
                        } else {
                            active_count.fetch_add(1, Ordering::Relaxed);
                            if stream_tx.send(boxed).await.is_err() {
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
        });
    }

    /// Starts H2 pool client on an underlying stream.
    pub fn start_client<S: crate::stream::AsyncStream>(&self, stream: S) {
        let control_stream = Arc::clone(&self.control_stream);
        let control_notify = Arc::clone(&self.control_notify);
        let send_request = Arc::clone(&self.send_request);
        let is_ready = Arc::clone(&self.is_ready);

        tokio::spawn(async move {
            let (mut client, conn) = match h2::client::handshake(stream).await {
                Ok(pair) => pair,
                Err(_) => return,
            };

            // Spawn connection driver
            tokio::spawn(async move {
                let _ = conn.await;
            });

            // Open control stream (first stream)
            let req = Request::builder().uri("/").body(()).unwrap();
            match client.send_request(req, false) {
                Ok((res_future, send)) => {
                    tokio::spawn(async move {
                        if let Ok(res) = res_future.await {
                            let recv = res.into_body();
                            let boxed = box_stream(H2Stream::new(send, recv));
                            *control_stream.lock().await = Some(boxed);
                            is_ready.store(true, Ordering::SeqCst);
                            control_notify.notify_waiters();
                        }
                    });
                }
                Err(_) => return,
            }

            *send_request.lock().await = Some(client);
        });
    }
}

#[async_trait]
impl TransportPool for H2Pool {
    async fn incoming_get(&self, timeout: Duration) -> Result<(String, BoxedStream), PoolError> {
        let client_opt = self.send_request.lock().await.clone();
        if let Some(client) = client_opt {
            let req = Request::builder().uri("/data").body(()).unwrap();
            let mut ready_client = match tokio::time::timeout(timeout, client.ready()).await {
                Ok(Ok(c)) => c,
                _ => return Err(PoolError::Timeout),
            };
            match ready_client.send_request(req, false) {
                Ok((res_future, send)) => match tokio::time::timeout(timeout, res_future).await {
                    Ok(Ok(res)) => {
                        let recv = res.into_body();
                        let id = format!("{:08x}", rand::random::<u32>());
                        Ok((id, box_stream(H2Stream::new(send, recv))))
                    }
                    _ => Err(PoolError::Timeout),
                },
                Err(e) => Err(PoolError::Other(e.to_string())),
            }
        } else {
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

        // Try pre-buffered stream first
        {
            let mut rx = self.stream_rx.lock().await;
            if let Ok(stream) = rx.try_recv() {
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                return Ok(stream);
            }
        }

        let client_opt = self.send_request.lock().await.clone();
        if let Some(client) = client_opt {
            let req = Request::builder().uri("/data").body(()).unwrap();
            let mut ready_client = match tokio::time::timeout(timeout, client.ready()).await {
                Ok(Ok(c)) => c,
                _ => return Err(PoolError::Timeout),
            };
            match ready_client.send_request(req, false) {
                Ok((res_future, send)) => match tokio::time::timeout(timeout, res_future).await {
                    Ok(Ok(res)) => {
                        let recv = res.into_body();
                        Ok(box_stream(H2Stream::new(send, recv)))
                    }
                    _ => Err(PoolError::Timeout),
                },
                Err(e) => Err(PoolError::Other(e.to_string())),
            }
        } else {
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
