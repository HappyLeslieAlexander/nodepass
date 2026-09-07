use nodepass_transport::stream::AsyncStream;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bidirectional data pump between two asynchronous streams.
/// Supports half-close FIN propagation and per-read idle timeouts without task/connection leaks.
pub async fn data_exchange<S1, S2>(
    s1: S1,
    s2: S2,
    idle_timeout: Duration,
    buf_size: usize,
) -> io::Result<()>
where
    S1: AsyncStream,
    S2: AsyncStream,
{
    data_exchange_with_stats(s1, s2, idle_timeout, buf_size, None, None, None).await
}

/// Bidirectional data pump with traffic accounting (rx/tx atomic counters) and token-bucket rate limiting.
/// Uses tokio::select! with mutual shutdown cancellation to guarantee that when one side
/// errors or times out, the other side is immediately cancelled and both streams are closed cleanly.
pub async fn data_exchange_with_stats<S1, S2>(
    s1: S1,
    s2: S2,
    idle_timeout: Duration,
    buf_size: usize,
    rx: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    tx: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    rate: Option<nodepass_transport::rate::RateLimiter>,
) -> io::Result<()>
where
    S1: AsyncStream,
    S2: AsyncStream,
{
    let (mut r1, mut w1) = tokio::io::split(s1);
    let (mut r2, mut w2) = tokio::io::split(s2);

    let rx_clone = rx;
    let rate_clone = rate.clone();
    let pump1 = async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            let read_fut = r1.read(&mut buf);
            let n = if idle_timeout > Duration::ZERO {
                match tokio::time::timeout(idle_timeout, read_fut).await {
                    Ok(res) => match res {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = w2.shutdown().await;
                            return Err(e);
                        }
                    },
                    Err(_) => {
                        let _ = w2.shutdown().await;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection read timed out",
                        ));
                    }
                }
            } else {
                match read_fut.await {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = w2.shutdown().await;
                        return Err(e);
                    }
                }
            };

            if n == 0 {
                // EOF on s1: propagate half-close FIN to s2
                let _ = w2.shutdown().await;
                break;
            }

            if let Some(ref rx_cnt) = rx_clone {
                rx_cnt.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
            if let Some(ref r_limit) = rate_clone {
                r_limit.wait_read(n).await;
            }

            w2.write_all(&buf[..n]).await?;
            w2.flush().await?;
        }
        Ok::<(), io::Error>(())
    };

    let pump2 = async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            let read_fut = r2.read(&mut buf);
            let n = if idle_timeout > Duration::ZERO {
                match tokio::time::timeout(idle_timeout, read_fut).await {
                    Ok(res) => match res {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = w1.shutdown().await;
                            return Err(e);
                        }
                    },
                    Err(_) => {
                        let _ = w1.shutdown().await;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection read timed out",
                        ));
                    }
                }
            } else {
                match read_fut.await {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = w1.shutdown().await;
                        return Err(e);
                    }
                }
            };

            if n == 0 {
                // EOF on s2: propagate half-close FIN to s1
                let _ = w1.shutdown().await;
                break;
            }

            if let Some(ref tx_cnt) = tx {
                tx_cnt.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
            if let Some(ref r_limit) = rate {
                r_limit.wait_write(n).await;
            }

            w1.write_all(&buf[..n]).await?;
            w1.flush().await?;
        }
        Ok::<(), io::Error>(())
    };

    tokio::pin!(pump1);
    tokio::pin!(pump2);

    tokio::select! {
        res1 = &mut pump1 => {
            match res1 {
                Ok(()) => pump2.await,
                Err(e) => Err(e),
            }
        }
        res2 = &mut pump2 => {
            match res2 {
                Ok(()) => pump1.await,
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_data_exchange() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (c2, mut s2) = tokio::io::duplex(1024);

        tokio::spawn(async move {
            data_exchange(c1, c2, Duration::ZERO, 1024).await.unwrap();
        });

        s1.write_all(b"ping from s1").await.unwrap();
        let mut buf = [0u8; 12];
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping from s1");

        s2.write_all(b"pong from s2").await.unwrap();
        let mut buf2 = [0u8; 12];
        s1.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong from s2");
    }

    #[tokio::test]
    async fn test_data_exchange_with_timeout_propagates_fin() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (c2, mut s2) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move {
            data_exchange(c1, c2, Duration::from_secs(5), 1024).await
        });

        s1.write_all(b"hello with timeout").await.unwrap();
        let mut buf = [0u8; 18];
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello with timeout");

        // Half-close s1
        drop(s1);

        // s2 should receive EOF
        let mut eof_buf = [0u8; 16];
        let n = s2.read(&mut eof_buf).await.unwrap();
        assert_eq!(n, 0);

        // Drop s2 to close reverse path
        drop(s2);

        let res = handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_data_exchange_timeout_cancels_peer() {
        let (c1, _s1) = tokio::io::duplex(1024);
        let (c2, _s2) = tokio::io::duplex(1024);

        // Idle timeout of 50ms. Neither side sends anything.
        let res = tokio::time::timeout(
            Duration::from_millis(500),
            data_exchange(c1, c2, Duration::from_millis(50), 1024),
        ).await;

        assert!(res.is_ok(), "data_exchange did not complete within 500ms");
        let exchange_res = res.unwrap();
        assert!(exchange_res.is_err());
        assert_eq!(exchange_res.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
