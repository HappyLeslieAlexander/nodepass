use parking_lot::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Token-bucket rate limiter for read and write bandwidth control independently.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    read_rate: i64,  // bytes/sec
    write_rate: i64, // bytes/sec
    read_tokens: Arc<AtomicI64>,
    write_tokens: Arc<AtomicI64>,
    last_update: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(read_bytes_per_sec: u64, write_bytes_per_sec: u64) -> Option<Self> {
        if read_bytes_per_sec == 0 && write_bytes_per_sec == 0 {
            return None;
        }

        let r_rate = if read_bytes_per_sec == 0 {
            1i64 << 40 // unlimited
        } else {
            read_bytes_per_sec as i64
        };

        let w_rate = if write_bytes_per_sec == 0 {
            1i64 << 40 // unlimited
        } else {
            write_bytes_per_sec as i64
        };

        Some(Self {
            read_rate: r_rate,
            write_rate: w_rate,
            read_tokens: Arc::new(AtomicI64::new(r_rate)),
            write_tokens: Arc::new(AtomicI64::new(w_rate)),
            last_update: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Asynchronously waits for read tokens to become available and consumes them.
    pub async fn wait_read(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.wait_tokens(bytes as i64, &self.read_tokens, self.read_rate)
            .await;
    }

    /// Asynchronously waits for write tokens to become available and consumes them.
    pub async fn wait_write(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.wait_tokens(bytes as i64, &self.write_tokens, self.write_rate)
            .await;
    }

    async fn wait_tokens(&self, bytes: i64, tokens_cell: &AtomicI64, max_rate: i64) {
        loop {
            self.refill();

            let curr = tokens_cell.load(Ordering::Relaxed);
            if curr >= bytes {
                if tokens_cell
                    .compare_exchange_weak(curr, curr - bytes, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            } else {
                // Not enough tokens: compute wait duration
                let needed = bytes - curr;
                let wait_secs = (needed as f64) / (max_rate as f64);
                let wait_duration = Duration::from_secs_f64(wait_secs.max(0.001).min(1.0));
                tokio::time::sleep(wait_duration).await;
            }
        }
    }

    fn refill(&self) {
        let mut last = self.last_update.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);
        if elapsed > Duration::from_millis(1) {
            let elapsed_secs = elapsed.as_secs_f64();
            let read_add = (self.read_rate as f64 * elapsed_secs) as i64;
            let write_add = (self.write_rate as f64 * elapsed_secs) as i64;

            add_tokens(&self.read_tokens, read_add, self.read_rate);
            add_tokens(&self.write_tokens, write_add, self.write_rate);

            *last = now;
        }
    }
}

fn add_tokens(cell: &AtomicI64, add: i64, max: i64) {
    if add <= 0 {
        return;
    }
    let mut curr = cell.load(Ordering::Relaxed);
    loop {
        let new_val = (curr + add).min(max);
        match cell.compare_exchange_weak(curr, new_val, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => curr = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let rl = RateLimiter::new(100_000, 100_000).unwrap();
        // Should consume immediately when full
        rl.wait_read(10_000).await;
        rl.wait_write(10_000).await;
    }
}
