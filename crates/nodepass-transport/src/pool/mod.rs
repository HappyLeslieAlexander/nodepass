use crate::stream::BoxedStream;
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

pub mod h2_pool;
pub mod quic_pool;
pub mod tcp_pool;
pub mod ws_pool;

pub use h2_pool::*;
pub use quic_pool::*;
pub use tcp_pool::*;
pub use ws_pool::*;

#[derive(Error, Debug)]
pub enum PoolError {
    #[error("Pool timeout waiting for connection")]
    Timeout,
    #[error("Pool closed or stopped")]
    Closed,
    #[error("Connection not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transport error: {0}")]
    Other(String),
}

/// Abstract connection pool interface managing pre-established tunnel connections.
#[async_trait]
pub trait TransportPool: Send + Sync {
    /// Retrieves a connection from the incoming pool queue, assigning it a unique ID.
    async fn incoming_get(&self, timeout: Duration) -> Result<(String, BoxedStream), PoolError>;

    /// Retrieves a specific connection from the outgoing pool queue by ID (e.g. "00000000" for control).
    async fn outgoing_get(&self, id: &str, timeout: Duration) -> Result<BoxedStream, PoolError>;

    /// Closes all connections in the pool and forces re-establishment.
    async fn flush(&self);

    /// Closes all pool resources and background workers.
    async fn close(&self);

    /// Returns true if the pool is initialized and ready (control connection available).
    fn is_ready(&self) -> bool;

    /// Returns the current number of active/available connections in the pool.
    fn active(&self) -> usize;

    /// Returns the maximum capacity of the pool.
    fn capacity(&self) -> usize;

    /// Increments the pool error counter.
    fn add_error(&self);

    /// Resets the pool error counter to zero.
    fn reset_error(&self);

    /// Returns the current error counter.
    fn error_count(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_h2_pool_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server_pool = H2Pool::new(16);
        let client_pool = H2Pool::new(16);

        server_pool.start_server(server_io);
        client_pool.start_client(client_io, 4);

        // Claim control connection
        let mut server_ctrl = server_pool.outgoing_get("00000000", Duration::from_secs(3)).await.unwrap();
        let mut client_ctrl = client_pool.outgoing_get("00000000", Duration::from_secs(3)).await.unwrap();

        client_ctrl.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server_ctrl.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Wait for pool streams to be established
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Data stream roundtrip
        let (id, mut server_stream) = server_pool.incoming_get(Duration::from_secs(3)).await.unwrap();
        assert!(!id.is_empty());
        let mut client_stream = client_pool.outgoing_get(&id, Duration::from_secs(3)).await.unwrap();

        server_stream.write_all(b"hello h2 stream").await.unwrap();
        let mut buf2 = [0u8; 15];
        client_stream.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello h2 stream");
    }

    #[tokio::test]
    async fn test_ws_pool_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_pool = WsPool::new(16);
        let client_pool = WsPool::new(16);

        server_pool.start_server(listener, None);
        let ws_url = format!("ws://{}/", addr);
        client_pool.start_client(addr, ws_url, 2, None);

        // Claim control connection
        let mut server_ctrl = server_pool.outgoing_get("00000000", Duration::from_secs(3)).await.unwrap();
        let mut client_ctrl = client_pool.outgoing_get("00000000", Duration::from_secs(3)).await.unwrap();

        client_ctrl.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server_ctrl.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
