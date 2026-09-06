use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;

/// Atomic traffic counters and connection slot manager for a tunnel endpoint.
#[derive(Debug, Clone)]
pub struct Stats {
    pub tcp_rx: Arc<AtomicU64>,
    pub tcp_tx: Arc<AtomicU64>,
    pub udp_rx: Arc<AtomicU64>,
    pub udp_tx: Arc<AtomicU64>,
    pub tcp_slot: Arc<AtomicI32>,
    pub udp_slot: Arc<AtomicI32>,
    pub slot_limit: i32,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new(65536)
    }
}

impl Stats {
    pub fn new(slot_limit: i32) -> Self {
        Self {
            tcp_rx: Arc::new(AtomicU64::new(0)),
            tcp_tx: Arc::new(AtomicU64::new(0)),
            udp_rx: Arc::new(AtomicU64::new(0)),
            udp_tx: Arc::new(AtomicU64::new(0)),
            tcp_slot: Arc::new(AtomicI32::new(0)),
            udp_slot: Arc::new(AtomicI32::new(0)),
            slot_limit,
        }
    }

    /// Attempts to acquire a slot for a TCP or UDP session.
    /// Returns true if under slot_limit (or slot_limit == 0), false otherwise.
    pub fn try_acquire_slot(&self, is_udp: bool) -> bool {
        if self.slot_limit <= 0 {
            if is_udp {
                self.udp_slot.fetch_add(1, Ordering::Relaxed);
            } else {
                self.tcp_slot.fetch_add(1, Ordering::Relaxed);
            }
            return true;
        }

        loop {
            let tcps = self.tcp_slot.load(Ordering::Relaxed);
            let udps = self.udp_slot.load(Ordering::Relaxed);
            if tcps + udps >= self.slot_limit {
                return false;
            }

            if is_udp {
                if self
                    .udp_slot
                    .compare_exchange_weak(udps, udps + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            } else {
                if self
                    .tcp_slot
                    .compare_exchange_weak(tcps, tcps + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            }
        }
    }

    /// Releases a previously acquired slot.
    pub fn release_slot(&self, is_udp: bool) {
        if is_udp {
            let mut curr = self.udp_slot.load(Ordering::Relaxed);
            while curr > 0 {
                match self
                    .udp_slot
                    .compare_exchange_weak(curr, curr - 1, Ordering::SeqCst, Ordering::Relaxed)
                {
                    Ok(_) => break,
                    Err(actual) => curr = actual,
                }
            }
        } else {
            let mut curr = self.tcp_slot.load(Ordering::Relaxed);
            while curr > 0 {
                match self
                    .tcp_slot
                    .compare_exchange_weak(curr, curr - 1, Ordering::SeqCst, Ordering::Relaxed)
                {
                    Ok(_) => break,
                    Err(actual) => curr = actual,
                }
            }
        }
    }

    /// Gets current traffic statistics.
    pub fn snapshot(&self) -> (u64, u64, u64, u64, i32, i32) {
        (
            self.tcp_rx.load(Ordering::Relaxed),
            self.tcp_tx.load(Ordering::Relaxed),
            self.udp_rx.load(Ordering::Relaxed),
            self.udp_tx.load(Ordering::Relaxed),
            self.tcp_slot.load(Ordering::Relaxed),
            self.udp_slot.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_acquisition_and_release() {
        let stats = Stats::new(2);
        assert!(stats.try_acquire_slot(false)); // TCP slot 1
        assert!(stats.try_acquire_slot(true));  // UDP slot 1, total 2
        assert!(!stats.try_acquire_slot(false)); // Limit reached!
        assert!(!stats.try_acquire_slot(true));

        stats.release_slot(false);
        assert!(stats.try_acquire_slot(false)); // Can acquire again
    }
}
