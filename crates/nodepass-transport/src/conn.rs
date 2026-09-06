use crate::rate::RateLimiter;
use crate::stream::AsyncStream;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Stream wrapper that atomically counts RX/TX bytes and applies rate limiting.
pub struct StatStream<S> {
    inner: S,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    rate: Option<RateLimiter>,
}

impl<S: AsyncStream> StatStream<S> {
    pub fn new(
        inner: S,
        rx: Arc<AtomicU64>,
        tx: Arc<AtomicU64>,
        rate: Option<RateLimiter>,
    ) -> Self {
        Self {
            inner,
            rx,
            tx,
            rate,
        }
    }

    pub fn rx(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.rx)
    }

    pub fn tx(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.tx)
    }

    pub fn rate(&self) -> Option<&RateLimiter> {
        self.rate.as_ref()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    self.rx.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.tx.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
