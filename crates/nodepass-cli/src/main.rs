use clap::{Args, Parser, Subcommand};
use dashmap::DashMap;
use nodepass_core::config::TunnelConfig;
use nodepass_master::mcp::McpHandler;
use nodepass_master::process::ProcessManager;
use nodepass_master::state::StateManager;
use nodepass_master::web::{create_router, AppState};
use nodepass_tunnel::client::TunnelClient;
use nodepass_tunnel::server::TunnelServer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;

const VERSION: &str = "1.1.1";

#[derive(Parser, Debug)]
#[command(name = "nodepass", version = VERSION, about = "High-performance reverse tunnel system")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Direct URL format: scheme://[password@]tunnel_addr:port/target_addr:port?params
    #[arg(trailing_var_arg = true)]
    raw_args: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start tunnel in server mode
    Server(ServerArgs),
    /// Start tunnel in client mode
    Client(ClientArgs),
    /// Start master controller
    Master(MasterArgs),
}

#[derive(Args, Debug, Default)]
struct ServerArgs {
    #[arg(short = 'p', long = "password", env = "NODEPASS_PASSWORD")]
    password: Option<String>,
    #[arg(short = 'l', long = "listen")]
    tunnel_addr: Option<String>,
    #[arg(short = 't', long = "target")]
    target_addr: Option<String>,
    #[arg(long = "tls", default_value = "0")]
    tls: String,
    #[arg(long = "pool", default_value = "0")]
    pool: String,
    #[arg(long = "mode", default_value = "0")]
    mode: String,
    #[arg(long = "log", default_value = "info")]
    log: String,
}

#[derive(Args, Debug, Default)]
struct ClientArgs {
    #[arg(short = 'p', long = "password", env = "NODEPASS_PASSWORD")]
    password: Option<String>,
    #[arg(short = 's', long = "server")]
    tunnel_addr: Option<String>,
    #[arg(short = 't', long = "target")]
    target_addr: Option<String>,
    #[arg(long = "tls", default_value = "0")]
    tls: String,
    #[arg(long = "pool", default_value = "0")]
    pool: String,
    #[arg(long = "mode", default_value = "0")]
    mode: String,
    #[arg(long = "log", default_value = "info")]
    log: String,
}

#[derive(Args, Debug, Default)]
struct MasterArgs {
    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1:8080")]
    listen: String,
    #[arg(short = 'k', long = "key", env = "NODEPASS_API_KEY")]
    api_key: Option<String>,
    #[arg(long = "prefix", default_value = "/api/v1")]
    prefix: String,
    #[arg(long = "log", default_value = "info")]
    log: String,
}

fn init_logger(log_level: &str) {
    let filter = match log_level {
        "debug" => "debug",
        "warn" => "warn",
        "error" => "error",
        "none" => "off",
        _ => "info",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

pub fn build_tunnel_url(
    scheme: &str,
    tunnel_addr: &str,
    target_addr: &str,
    password: &str,
    params: &[(&str, &str)],
) -> Result<String, Box<dyn std::error::Error>> {
    let dummy = format!("{}://{}", scheme, tunnel_addr);
    let mut parsed = Url::parse(&dummy)?;

    if !password.is_empty() {
        parsed
            .set_username(password)
            .map_err(|_| "Failed to set username in URL")?;
    }

    let path = if target_addr.starts_with('/') {
        target_addr.to_string()
    } else {
        format!("/{}", target_addr)
    };
    parsed.set_path(&path);

    {
        let mut query = parsed.query_pairs_mut();
        query.clear();
        for (k, v) in params {
            if !v.is_empty() {
                query.append_pair(k, v);
            }
        }
    }

    Ok(parsed.to_string())
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut stream) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            stream.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Check if invoked with URL syntax directly: nodepass <url>
    if args.len() >= 2 && args[1].contains("://") {
        return run_url(&args[1]).await;
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Server(s)) => {
            init_logger(&s.log);
            let addr = s.tunnel_addr.unwrap_or_else(|| "0.0.0.0:8080".to_string());
            let target = s.target_addr.unwrap_or_else(|| "127.0.0.1:80".to_string());
            let pwd = s.password.unwrap_or_default();
            let url_str = build_tunnel_url(
                "server",
                &addr,
                &target,
                &pwd,
                &[
                    ("tls", &s.tls),
                    ("type", &s.pool),
                    ("mode", &s.mode),
                    ("log", &s.log),
                ],
            )?;
            run_url(&url_str).await
        }
        Some(Commands::Client(c)) => {
            init_logger(&c.log);
            let addr = c
                .tunnel_addr
                .unwrap_or_else(|| "127.0.0.1:8080".to_string());
            let target = c.target_addr.unwrap_or_else(|| "127.0.0.1:80".to_string());
            let pwd = c.password.unwrap_or_default();
            let url_str = build_tunnel_url(
                "client",
                &addr,
                &target,
                &pwd,
                &[
                    ("tls", &c.tls),
                    ("type", &c.pool),
                    ("mode", &c.mode),
                    ("log", &c.log),
                ],
            )?;
            run_url(&url_str).await
        }
        Some(Commands::Master(m)) => {
            init_logger(&m.log);
            run_master(
                &m.listen,
                m.api_key.as_deref(),
                &m.prefix,
                Some(m.log),
                None,
                None,
                None,
            )
            .await
        }
        None => {
            if !cli.raw_args.is_empty() && cli.raw_args[0].contains("://") {
                run_url(&cli.raw_args[0]).await
            } else {
                println!("NodePass Rust {}", VERSION);
                println!("Run 'nodepass --help' for usage");
                Ok(())
            }
        }
    }
}

async fn run_url(url_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_url = Url::parse(url_str)?;
    let config = TunnelConfig::parse(url_str)?;
    init_logger(&config.log_level);

    match parsed_url.scheme() {
        "client" => {
            info!("Starting NodePass client: {}", url_str);
            let client = Arc::new(TunnelClient::new(config));
            let mut client_task = {
                let client = Arc::clone(&client);
                tokio::spawn(async move { client.run().await })
            };
            tokio::select! {
                res = &mut client_task => {
                    match res {
                        Ok(Ok(())) => {},
                        Ok(Err(e)) => return Err(e.into()),
                        Err(e) => return Err(e.into()),
                    }
                }
                _ = wait_for_shutdown_signal() => {
                    info!("Shutdown signal received, stopping client...");
                    client.stop();
                    let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
                }
            }
        }
        "server" => {
            info!("Starting NodePass server: {}", url_str);
            let server = Arc::new(TunnelServer::new(config));
            let mut server_task = {
                let server = Arc::clone(&server);
                tokio::spawn(async move { server.run().await })
            };
            tokio::select! {
                res = &mut server_task => {
                    match res {
                        Ok(Ok(())) => {},
                        Ok(Err(e)) => return Err(e.into()),
                        Err(e) => return Err(e.into()),
                    }
                }
                _ = wait_for_shutdown_signal() => {
                    info!("Shutdown signal received, stopping server...");
                    server.stop();
                    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
                }
            }
        }
        "master" => {
            let listen = format!(
                "{}:{}",
                parsed_url.host_str().unwrap_or("127.0.0.1"),
                parsed_url.port().unwrap_or(8080)
            );
            let prefix = parsed_url.path();
            let prefix = if prefix.is_empty() || prefix == "/" {
                "/api/v1"
            } else {
                prefix
            };
            let key = if let Some(pass) = parsed_url.password() {
                if !pass.is_empty() {
                    Some(pass)
                } else if !parsed_url.username().is_empty() {
                    Some(parsed_url.username())
                } else {
                    None
                }
            } else if !parsed_url.username().is_empty() {
                Some(parsed_url.username())
            } else {
                None
            };
            let mut log_level = None;
            let mut tls_code = None;
            let mut crt_path = None;
            let mut key_path = None;
            for (k, v) in parsed_url.query_pairs() {
                match k.as_ref() {
                    "log" => log_level = Some(v.to_string()),
                    "tls" => tls_code = Some(v.to_string()),
                    "crt" => crt_path = Some(v.to_string()),
                    "key" => key_path = Some(v.to_string()),
                    _ => {}
                }
            }
            run_master(
                &listen, key, prefix, log_level, tls_code, crt_path, key_path,
            )
            .await?;
        }
        _ => {
            return Err(format!("Unknown scheme: {}", parsed_url.scheme()).into());
        }
    }

    Ok(())
}

async fn run_master(
    listen_addr: &str,
    api_key_opt: Option<&str>,
    prefix: &str,
    log_level: Option<String>,
    tls_code: Option<String>,
    crt_path: Option<String>,
    key_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = listen_addr.parse()?;
    let instances = Arc::new(DashMap::new());
    let (event_tx, _) = tokio::sync::broadcast::channel(1024);
    let process_mgr = Arc::new(ProcessManager::new(
        Arc::clone(&instances),
        event_tx.clone(),
    ));
    let state_mgr = Arc::new(StateManager::new("nodepass.json"));
    let _ = state_mgr.load(&instances);

    let api_key = api_key_opt
        .map(|k| k.to_string())
        .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));

    info!("Master started on {} with prefix {}", bind_addr, prefix);
    info!("API Key: {}", api_key);

    let mcp_handler = Arc::new(McpHandler::new(
        Arc::clone(&instances),
        Arc::clone(&process_mgr),
        Arc::clone(&state_mgr),
        VERSION.to_string(),
        "master-1".to_string(),
        "nodepass-master".to_string(),
        "localhost".to_string(),
        Instant::now(),
    ));

    let state = AppState {
        instances: Arc::clone(&instances),
        process_mgr: Arc::clone(&process_mgr),
        state_mgr: Arc::clone(&state_mgr),
        event_tx,
        mcp_handler,
        api_key,
        prefix: prefix.to_string(),
        version: VERSION.to_string(),
        mid: "master-1".to_string(),
        alias: Arc::new(parking_lot::RwLock::new("nodepass-master".to_string())),
        hostname: "localhost".to_string(),
        start_time: Instant::now(),
        log_level,
        tls_code,
        crt_path,
        key_path,
    };

    let router = create_router(state);
    let listener = TcpListener::bind(bind_addr).await?;

    let state_mgr_clone = Arc::clone(&state_mgr);
    let instances_clone = Arc::clone(&instances);
    let process_mgr_clone = Arc::clone(&process_mgr);

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            wait_for_shutdown_signal().await;
            info!("Shutdown signal received, stopping master and instances...");
            process_mgr_clone.stop_all().await;
            let _ = state_mgr_clone.save(&instances_clone).await;
            info!("Master state cleanly saved.");
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tunnel_url_escaping() {
        let url_str = build_tunnel_url(
            "server",
            "127.0.0.1:8080",
            "127.0.0.1:80",
            "my@pass?mode=1#target",
            &[("tls", "0"), ("mode", "2")],
        )
        .expect("build tunnel url");

        assert!(url_str.starts_with("server://"));
        assert!(url_str.contains("my%40pass%3Fmode%3D1%23target@127.0.0.1:8080/127.0.0.1:80"));
        assert!(url_str.contains("mode=2"));

        let cfg = TunnelConfig::parse(&url_str).expect("parse built url");
        assert_eq!(cfg.tunnel_key, "my@pass?mode=1#target");
        assert_eq!(cfg.run_mode, "2");
    }

    #[test]
    fn test_master_default_listen_address() {
        let _args = MasterArgs::default();
        // default value from clap attribute
        let cli = Cli::try_parse_from(["nodepass", "master"]).expect("parse cli");
        if let Some(Commands::Master(m)) = cli.command {
            assert_eq!(m.listen, "127.0.0.1:8080");
        } else {
            panic!("expected master command");
        }
    }

    #[test]
    fn test_env_credentials() {
        std::env::set_var("NODEPASS_PASSWORD", "env_secret_123");
        std::env::set_var("NODEPASS_API_KEY", "env_key_456");

        let cli_server = Cli::try_parse_from(["nodepass", "server"]).expect("parse server cli");
        if let Some(Commands::Server(s)) = cli_server.command {
            assert_eq!(s.password.as_deref(), Some("env_secret_123"));
        } else {
            panic!("expected server command");
        }

        let cli_master = Cli::try_parse_from(["nodepass", "master"]).expect("parse master cli");
        if let Some(Commands::Master(m)) = cli_master.command {
            assert_eq!(m.api_key.as_deref(), Some("env_key_456"));
        } else {
            panic!("expected master command");
        }

        std::env::remove_var("NODEPASS_PASSWORD");
        std::env::remove_var("NODEPASS_API_KEY");
    }

    #[test]
    fn test_master_url_credential_extraction() {
        let u1 = Url::parse("master://mysecret@127.0.0.1:8080/api/v1").unwrap();
        let key1 = if let Some(pass) = u1.password() {
            if !pass.is_empty() {
                Some(pass)
            } else if !u1.username().is_empty() {
                Some(u1.username())
            } else {
                None
            }
        } else if !u1.username().is_empty() {
            Some(u1.username())
        } else {
            None
        };
        assert_eq!(key1, Some("mysecret"));

        let u2 = Url::parse("master://:anothersecret@127.0.0.1:8080/api/v1").unwrap();
        let key2 = if let Some(pass) = u2.password() {
            if !pass.is_empty() {
                Some(pass)
            } else if !u2.username().is_empty() {
                Some(u2.username())
            } else {
                None
            }
        } else if !u2.username().is_empty() {
            Some(u2.username())
        } else {
            None
        };
        assert_eq!(key2, Some("anothersecret"));
    }
}
