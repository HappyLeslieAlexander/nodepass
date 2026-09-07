# NodePass Rust Workspace Engineering Rules & Invariants

All agents and contributors working in this repository must strictly adhere to the following architecture, protocol parity, and async networking invariants:

## 1. Wire-Level & Protocol Parity with Go NodePass
- **100% Protocol Compatibility**: Wire formats, signal JSON schemas (`action`, `id`, `remote`, `fp`), XOR+Base64 obfuscation, and 2-byte BE UDP framing must remain byte-for-byte compatible with Go NodePass.
- **Preserve HTTP Verbs & Endpoints**: Master control APIs must adhere to Go specifications (e.g., `PATCH /api/v1/instances/:id` for instance state actions). Never change REST paths or HTTP verbs arbitrarily.
- **Config & URL Invariants**: 
  - `pool_type == "1"` (QUIC) mandates TLS upgrade; `pool_type == "2"` (WebSocket) must NOT force TLS upgrade (must allow plaintext WS matching Go).
  - Tunnel key derivation must match Go's precedence: username -> password -> FNV-1a(port).

## 2. Async Networking & Concurrency Guardrails (Tokio)
- **Mutual Cancellation in Bidirectional Pumps**:
  - NEVER use `tokio::join!` across two independent stream pumps without cancellation propagation.
  - ALWAYS use `tokio::select!` or an explicit `CancellationToken`. When one pump encounters EOF, timeout, or error, it must immediately issue `shutdown()` and cancel the peer pump to prevent task and socket leaks.
- **Scoped Listener Lifecycles (Prevent `EADDRINUSE`)**:
  - Any background listener task (TCP `TcpListener`, UDP `UdpSocket`, H2 listener) spawned during a session MUST be tied to a scoped `watch::channel` or `CancellationToken` (e.g., `SessionGuard`).
  - When the control session disconnects or an auto-restart is triggered, all child listeners must be terminated and their ports released before entering cooldown.
- **Resilient Handshake Listeners (Anti-DoS)**:
  - Tunnel server handshake listeners must NEVER be written as a one-shot accept.
  - Handshake must run in a resilient accept loop: reject invalid auth tokens with `401 Unauthorized`, close the rogue connection, and continue listening for legitimate clients.
- **Socket Options Invariant**:
  - Every accepted and dialed TCP stream used for tunneling or proxying MUST have `set_nodelay(true)` explicitly configured to disable Nagle's algorithm.
  - Configure TCP keepalive to detect silent dead connections.

## 3. Cross-Platform Compilation & Verification Hygiene
- **Conditional Compilation (`cfg`) Discipline**:
  - Whenever code is placed under `#[cfg(target_os = "linux")]` or other non-host targets, verify that all symbols, imports (e.g., `std::fs`), and bindings (`mut`) are strictly valid.
  - Implement unit test mocks or test fixtures (e.g., mock `/proc` data) so target-specific logic can be tested on any host OS.
- **CI / Build Gate**:
  - Code changes must always pass:
    1. `cargo test --workspace` (100% tests passing)
    2. `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings)
    3. `cargo fmt --check` (100% format compliance)
