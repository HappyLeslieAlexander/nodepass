use dashmap::DashMap;
use nodepass_transport::stream::BoxedStream;
use parking_lot::Mutex as SyncMutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct UdpSession {
    pub stream: Arc<Mutex<BoxedStream>>,
    pub last_active: Arc<SyncMutex<Instant>>,
}

/// Thread-safe UDP session table mapping external client addresses to persistent streams.
#[derive(Clone)]
pub struct UdpSessionManager {
    sessions: Arc<DashMap<SocketAddr, UdpSession>>,
    timeout: Duration,
}

impl UdpSessionManager {
    pub fn new(timeout: Duration) -> Self {
        let mgr = Self {
            sessions: Arc::new(DashMap::new()),
            timeout,
        };

        // Spawn background cleanup task
        let sessions = Arc::clone(&mgr.sessions);
        tokio::spawn(async move {
            let interval = Duration::from_secs(5);
            loop {
                tokio::time::sleep(interval).await;
                let now = Instant::now();
                sessions.retain(|_addr, session| {
                    let last = *session.last_active.lock();
                    now.duration_since(last) < timeout
                });
            }
        });

        mgr
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<UdpSession> {
        self.sessions.get(addr).map(|entry| {
            let session = entry.value();
            *session.last_active.lock() = Instant::now();
            UdpSession {
                stream: Arc::clone(&session.stream),
                last_active: Arc::clone(&session.last_active),
            }
        })
    }

    pub fn insert(&self, addr: SocketAddr, stream: BoxedStream) -> UdpSession {
        let session = UdpSession {
            stream: Arc::new(Mutex::new(stream)),
            last_active: Arc::new(SyncMutex::new(Instant::now())),
        };
        self.sessions.insert(
            addr,
            UdpSession {
                stream: Arc::clone(&session.stream),
                last_active: Arc::clone(&session.last_active),
            },
        );
        session
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.sessions.remove(addr);
    }
}
