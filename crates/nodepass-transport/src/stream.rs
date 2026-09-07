use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Unified trait for full-duplex asynchronous streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> AsyncStream for T {}

/// Boxed dynamic async stream.
pub type BoxedStream = Box<dyn AsyncStream>;

/// A wrapper to easily convert an object implementing AsyncRead + AsyncWrite into a BoxedStream.
pub fn box_stream<T: AsyncStream>(stream: T) -> BoxedStream {
    Box::new(stream)
}

/// A split stream wrapper combining separate AsyncRead and AsyncWrite handles.
pub struct SplitStream<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R, W> SplitStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for SplitStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for SplitStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// Configures standard production TCP socket options:
/// - TCP_NODELAY (disables Nagle algorithm to reduce latency for interactive traffic)
/// - SO_KEEPALIVE (probes every 15s to detect dead connections and prevent resource leaks)
pub fn configure_tcp_socket(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(15));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
    Ok(())
}

/// Returns true if an I/O error during accept or connect is transient (e.g. EMFILE, ENFILE, ECONNABORTED, EINTR).
pub fn is_transient_error(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    if let Some(code) = err.raw_os_error() {
        // EMFILE (24), ENFILE (23), ENOBUFS (55 on BSD/macOS, 105 on Linux), ENOMEM (12)
        if code == 24 || code == 23 || code == 12 || code == 55 || code == 105 {
            return true;
        }
    }
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    )
}

