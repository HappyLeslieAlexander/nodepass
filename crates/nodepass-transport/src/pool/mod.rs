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
