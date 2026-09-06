pub mod h2_adapter;
pub mod quic_adapter;
pub mod ws_adapter;

pub use h2_adapter::H2Stream;
pub use quic_adapter::QuinnStream;
pub use ws_adapter::WsStream;
