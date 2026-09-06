use nodepass_core::crypto::{decode_signal, encode_signal};
use nodepass_core::protocol::Signal;
use nodepass_transport::pool::TransportPool;
use nodepass_transport::stream::BoxedStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error};

pub struct ControlLoop {
    tunnel_key: String,
    pool: Arc<dyn TransportPool>,
    write_tx: mpsc::Sender<Signal>,
    write_rx: Arc<Mutex<mpsc::Receiver<Signal>>>,
    signal_tx: mpsc::Sender<Signal>,
    signal_rx: Arc<Mutex<mpsc::Receiver<Signal>>>,
    last_ping: Arc<Mutex<Instant>>,
    stop_flag: Arc<AtomicBool>,
}

impl ControlLoop {
    pub fn new(tunnel_key: impl Into<String>, pool: Arc<dyn TransportPool>) -> Self {
        let (write_tx, write_rx) = mpsc::channel(1024);
        let (signal_tx, signal_rx) = mpsc::channel(1024);
        Self {
            tunnel_key: tunnel_key.into(),
            pool,
            write_tx,
            write_rx: Arc::new(Mutex::new(write_rx)),
            signal_tx,
            signal_rx: Arc::new(Mutex::new(signal_rx)),
            last_ping: Arc::new(Mutex::new(Instant::now())),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn sender(&self) -> mpsc::Sender<Signal> {
        self.write_tx.clone()
    }

    pub async fn recv_signal(&self) -> Option<Signal> {
        let mut rx = self.signal_rx.lock().await;
        rx.recv().await
    }

    pub async fn send_signal(&self, sig: Signal) -> Result<(), mpsc::error::SendError<Signal>> {
        self.write_tx.send(sig).await
    }

    /// Spawns the control loop workers on the dedicated control stream.
    pub fn start(&self, control_stream: BoxedStream, report_interval: Duration, _tls_code_1: bool) {
        let (reader, mut writer) = tokio::io::split(control_stream);
        let mut buf_reader = BufReader::new(reader);

        let tunnel_key_bytes = self.tunnel_key.as_bytes().to_vec();
        let key_for_writer = tunnel_key_bytes.clone();
        let key_for_reader = tunnel_key_bytes.clone();

        let write_rx = Arc::clone(&self.write_rx);
        let signal_tx = self.signal_tx.clone();
        let stop_flag = Arc::clone(&self.stop_flag);

        // 1. Writer task
        tokio::spawn(async move {
            let mut rx = write_rx.lock().await;
            while let Some(signal) = rx.recv().await {
                if let Ok(json_bytes) = serde_json::to_vec(&signal) {
                    let wire_bytes = encode_signal(&json_bytes, &key_for_writer);
                    if writer.write_all(&wire_bytes).await.is_err() {
                        break;
                    }
                    let _ = writer.flush().await;
                }
            }
        });

        // 2. Reader task
        tokio::spawn(async move {
            const MAX_CONTROL_LINE_LEN: usize = 16384;
            let mut line = Vec::new();
            while !stop_flag.load(Ordering::Relaxed) {
                line.clear();
                let read_res = (&mut buf_reader)
                    .take(MAX_CONTROL_LINE_LEN as u64)
                    .read_until(b'\n', &mut line)
                    .await;
                match read_res {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        if line.len() >= MAX_CONTROL_LINE_LEN && !line.ends_with(b"\n") {
                            error!("Control signal line exceeded maximum allowed length (16KB)");
                            break;
                        }
                        match decode_signal(&line, &key_for_reader) {
                            Ok(plaintext) => match serde_json::from_slice::<Signal>(&plaintext) {
                                Ok(signal) => {
                                    if signal_tx.send(signal).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => error!("Control unmarshal error: {}", e),
                            },
                            Err(e) => error!("Control decode error: {}", e),
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // 3. Health check task
        let write_tx = self.write_tx.clone();
        let pool = Arc::clone(&self.pool);
        let last_ping = Arc::clone(&self.last_ping);
        let stop_flag_health = Arc::clone(&self.stop_flag);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(report_interval);
            while !stop_flag_health.load(Ordering::Relaxed) {
                interval.tick().await;

                // Check pool error rate
                if pool.active() > 0 && pool.error_count() > pool.active() / 2 {
                    let _ = write_tx.send(Signal::flush()).await;
                    pool.flush().await;
                    pool.reset_error();
                    debug!("Pool flushed due to error rate");
                }

                // Send ping
                *last_ping.lock().await = Instant::now();
                let _ = write_tx.send(Signal::ping()).await;
            }
        });
    }

    pub fn last_ping_time(&self) -> Arc<Mutex<Instant>> {
        Arc::clone(&self.last_ping)
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
