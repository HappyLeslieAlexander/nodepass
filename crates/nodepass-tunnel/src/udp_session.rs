use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Thread-safe UDP session table mapping external client addresses to channel senders.
/// Using channel senders eliminates lock contention between UDP frame reads and writes.
#[derive(Clone, Default)]
pub struct UdpSessionManager {
    sessions: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

impl UdpSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions.get(addr).map(|entry| entry.value().clone())
    }

    pub fn get_active(&self, addr: &SocketAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        if let Some(entry) = self.sessions.get(addr) {
            if !entry.value().is_closed() {
                return Some(entry.value().clone());
            }
            drop(entry);
            self.sessions.remove(addr);
        }
        None
    }

    pub fn insert(&self, addr: SocketAddr, sender: mpsc::Sender<Vec<u8>>) {
        self.sessions.insert(addr, sender);
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.sessions.remove(addr);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_session_manager_crud() {
        let mgr = UdpSessionManager::new();
        assert!(mgr.is_empty());

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (tx, _rx) = mpsc::channel(32);

        mgr.insert(addr, tx);
        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        let retrieved = mgr.get(&addr);
        assert!(retrieved.is_some());

        mgr.remove(&addr);
        assert_eq!(mgr.len(), 0);
        assert!(mgr.get(&addr).is_none());
    }
}
