use nodepass_core::config::TunnelConfig;
use nodepass_tunnel::client::TunnelClient;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn test_single_mode_forwarding() {
    // 1. Start an echo target server
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = target_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Find a free port for the tunnel listener
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Create single-mode client
    let url_str = format!("client://:testkey@{}/{}?mode=1", tunnel_addr, target_addr);
    let config = TunnelConfig::parse(&url_str).unwrap();
    let client = TunnelClient::new(config);

    tokio::spawn(async move {
        let _ = client.run_single_mode().await;
    });

    // Wait briefly for client listener to become active
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 4. Connect to tunnel listener and exchange data
    let mut conn = TcpStream::connect(tunnel_addr).await.unwrap();
    conn.write_all(b"hello nodepass single mode").await.unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello nodepass single mode");
}

#[tokio::test]
async fn test_pool_mode_client_to_server() {
    // 1. Start echo backend server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });

    // 2. Prepare tunnel server address
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Prepare client target listener address
    let client_target_free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_target_addr = client_target_free.local_addr().unwrap();
    drop(client_target_free);

    // 4. Start tunnel server (mode 2 => data_flow = "+", forwards from tunnel to echo_addr)
    let server_url = format!(
        "server://:mykey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, echo_addr
    );
    let server_cfg = TunnelConfig::parse(&server_url).unwrap();
    let server = nodepass_tunnel::server::TunnelServer::new(server_cfg);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server a moment to start handshake listener
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Start tunnel client (mode 2 => pool mode, data_flow = "+", listens on client_target_addr)
    let client_url = format!(
        "client://:mykey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, client_target_addr
    );
    let client_cfg = TunnelConfig::parse(&client_url).unwrap();
    let client = TunnelClient::new(client_cfg);

    tokio::spawn(async move {
        let _ = client.run_pool_mode().await;
    });

    // Wait for handshake, pool creation, and control connection
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 6. Connect to client_target_addr and send data
    let mut conn = match TcpStream::connect(client_target_addr).await {
        Ok(c) => c,
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            TcpStream::connect(client_target_addr).await.unwrap()
        }
    };

    conn.write_all(b"hello nodepass pooled mode").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello nodepass pooled mode");
}

#[tokio::test]
async fn test_udp_single_mode_forwarding() {
    // 1. Start an echo UDP target
    let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((n, src)) = echo_sock.recv_from(&mut buf).await {
            let _ = echo_sock.send_to(&buf[..n], src).await;
        }
    });

    // 2. Find a free port for the tunnel listener
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Create single-mode client
    let url_str = format!("client://:testkey@{}/{}?mode=1", tunnel_addr, echo_addr);
    let config = TunnelConfig::parse(&url_str).unwrap();
    let client = TunnelClient::new(config);

    tokio::spawn(async move {
        let _ = client.run_single_mode().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 4. Send UDP datagram to tunnel_addr
    let user_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    user_sock
        .send_to(b"hello udp single mode", tunnel_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), user_sock.recv_from(&mut buf))
        .await
        .expect("UDP single mode timeout")
        .expect("UDP recv error");
    assert_eq!(&buf[..n], b"hello udp single mode");
}

#[tokio::test]
async fn test_pool_mode_websocket() {
    // 1. Start echo backend server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });

    // 2. Prepare tunnel server address
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Prepare client target listener address
    let client_target_free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_target_addr = client_target_free.local_addr().unwrap();
    drop(client_target_free);

    // 4. Start tunnel server (mode 2 => type 2 WebSocket)
    let server_url = format!(
        "server://:mykey@{}/{}?mode=2&type=2&tls=0",
        tunnel_addr, echo_addr
    );
    let server_cfg = TunnelConfig::parse(&server_url).unwrap();
    let server = nodepass_tunnel::server::TunnelServer::new(server_cfg);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Start tunnel client (mode 2 => type 2 WebSocket)
    let client_url = format!(
        "client://:mykey@{}/{}?mode=2&type=2&tls=0",
        tunnel_addr, client_target_addr
    );
    let client_cfg = TunnelConfig::parse(&client_url).unwrap();
    let client = TunnelClient::new(client_cfg);

    tokio::spawn(async move {
        let _ = client.run_pool_mode().await;
    });

    tokio::time::sleep(Duration::from_millis(800)).await;

    // 6. Connect to client_target_addr and send data
    let mut conn = match TcpStream::connect(client_target_addr).await {
        Ok(c) => c,
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            TcpStream::connect(client_target_addr).await.unwrap()
        }
    };

    conn.write_all(b"hello nodepass ws mode").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello nodepass ws mode");
}

#[tokio::test]
async fn test_pool_mode_http2() {
    // 1. Start echo backend server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });

    // 2. Prepare tunnel server address
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Prepare client target listener address
    let client_target_free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_target_addr = client_target_free.local_addr().unwrap();
    drop(client_target_free);

    // 4. Start tunnel server (mode 2 => type 3 HTTP/2)
    let server_url = format!(
        "server://:mykey@{}/{}?mode=2&type=3&tls=0",
        tunnel_addr, echo_addr
    );
    let server_cfg = TunnelConfig::parse(&server_url).unwrap();
    let server = nodepass_tunnel::server::TunnelServer::new(server_cfg);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Start tunnel client (mode 2 => type 3 HTTP/2)
    let client_url = format!(
        "client://:mykey@{}/{}?mode=2&type=3&tls=0",
        tunnel_addr, client_target_addr
    );
    let client_cfg = TunnelConfig::parse(&client_url).unwrap();
    let client = TunnelClient::new(client_cfg);

    tokio::spawn(async move {
        let _ = client.run_pool_mode().await;
    });

    tokio::time::sleep(Duration::from_millis(800)).await;

    // 6. Connect to client_target_addr and send data
    let mut conn = match TcpStream::connect(client_target_addr).await {
        Ok(c) => c,
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            TcpStream::connect(client_target_addr).await.unwrap()
        }
    };

    conn.write_all(b"hello nodepass h2 mode").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello nodepass h2 mode");
}

#[tokio::test]
async fn test_udp_pool_mode_forwarding() {
    // 1. Echo UDP target server
    let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((n, src)) = echo_sock.recv_from(&mut buf).await {
            let _ = echo_sock.send_to(&buf[..n], src).await;
        }
    });

    // 2. Prepare tunnel server address
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    // 3. Prepare client target address
    let client_target_free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_target_addr = client_target_free.local_addr().unwrap();
    drop(client_target_free);

    // 4. Start tunnel server (mode 2 => type 0 TCP pool)
    let server_url = format!(
        "server://:mykey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, echo_addr
    );
    let server_cfg = TunnelConfig::parse(&server_url).unwrap();
    let server = nodepass_tunnel::server::TunnelServer::new(server_cfg);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Start tunnel client
    let client_url = format!(
        "client://:mykey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, client_target_addr
    );
    let client_cfg = TunnelConfig::parse(&client_url).unwrap();
    let client = TunnelClient::new(client_cfg);

    tokio::spawn(async move {
        let _ = client.run_pool_mode().await;
    });

    tokio::time::sleep(Duration::from_millis(600)).await;

    // 6. Send UDP datagram to client_target_addr
    let user_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    user_sock
        .send_to(b"hello nodepass udp pool", client_target_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), user_sock.recv_from(&mut buf))
        .await
        .expect("UDP pool mode timeout")
        .expect("UDP pool recv error");
    assert_eq!(&buf[..n], b"hello nodepass udp pool");
}

#[tokio::test]
async fn test_server_handshake_resilience_and_reconnection() {
    // 1. Backend echo
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });

    // 2. Prepare tunnel server address
    let free_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = free_listener.local_addr().unwrap();
    drop(free_listener);

    let client_target_free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_target_addr = client_target_free.local_addr().unwrap();
    drop(client_target_free);

    // 3. Start tunnel server
    let server_url = format!(
        "server://:correctkey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, echo_addr
    );
    let server_cfg = TunnelConfig::parse(&server_url).unwrap();
    let server = nodepass_tunnel::server::TunnelServer::new(server_cfg);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 4. Send probe / unauthorized connection to handshake port
    if let Ok(mut probe_conn) = TcpStream::connect(tunnel_addr).await {
        let _ = probe_conn
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrongtoken\r\n\r\n",
            )
            .await;
        let mut resp = [0u8; 512];
        let _ = probe_conn.read(&mut resp).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Connect authorized client
    let client_url = format!(
        "client://:correctkey@{}/{}?mode=2&type=0&tls=0",
        tunnel_addr, client_target_addr
    );
    let client_cfg = TunnelConfig::parse(&client_url).unwrap();
    let client = TunnelClient::new(client_cfg);
    tokio::spawn(async move {
        let _ = client.run_pool_mode().await;
    });

    tokio::time::sleep(Duration::from_millis(600)).await;

    // 6. Verify traffic passes through
    let mut conn = TcpStream::connect(client_target_addr).await.unwrap();
    conn.write_all(b"resilience test pass").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"resilience test pass");
}
