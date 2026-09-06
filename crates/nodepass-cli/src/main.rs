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
use std::time::Instant;
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
    #[arg(short = 'p', long = "password")]
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
    #[arg(short = 'p', long = "password")]
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
    #[arg(short = 'l', long = "listen", default_value = "0.0.0.0:8080")]
    listen: String,
    #[arg(short = 'k', long = "key")]
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
            let url_str = if pwd.is_empty() {
                format!("server://{}/{}?tls={}&type={}&mode={}", addr, target, s.tls, s.pool, s.mode)
            } else {
                format!("server://{}@{}/{}?tls={}&type={}&mode={}", pwd, addr, target, s.tls, s.pool, s.mode)
            };
            run_url(&url_str).await
        }
        Some(Commands::Client(c)) => {
            init_logger(&c.log);
            let addr = c.tunnel_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());
            let target = c.target_addr.unwrap_or_else(|| "127.0.0.1:80".to_string());
            let pwd = c.password.unwrap_or_default();
            let url_str = if pwd.is_empty() {
                format!("client://{}/{}?tls={}&type={}&mode={}", addr, target, c.tls, c.pool, c.mode)
            } else {
                format!("client://{}@{}/{}?tls={}&type={}&mode={}", pwd, addr, target, c.tls, c.pool, c.mode)
            };
            run_url(&url_str).await
        }
        Some(Commands::Master(m)) => {
            init_logger(&m.log);
            run_master(&m.listen, m.api_key.as_deref(), &m.prefix).await
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
    let log_level = parsed_url.query_pairs().find(|(k, _)| k == "log").map(|(_, v)| v.to_string()).unwrap_or_else(|| "info".to_string());
    init_logger(&log_level);

    let config = TunnelConfig::parse(url_str)?;

    match parsed_url.scheme() {
        "client" => {
            info!("Starting NodePass client: {}", url_str);
            let client = TunnelClient::new(config);
            client.run().await?;
        }
        "server" => {
            info!("Starting NodePass server: {}", url_str);
            let server = TunnelServer::new(config);
            server.run().await?;
        }
        "master" => {
            let listen = format!("{}:{}", parsed_url.host_str().unwrap_or("0.0.0.0"), parsed_url.port().unwrap_or(8080));
            let prefix = parsed_url.path();
            let prefix = if prefix.is_empty() || prefix == "/" { "/api/v1" } else { prefix };
            let key = parsed_url.password();
            run_master(&listen, key, prefix).await?;
        }
        _ => {
            return Err(format!("Unknown scheme: {}", parsed_url.scheme()).into());
        }
    }

    Ok(())
}

async fn run_master(listen_addr: &str, api_key_opt: Option<&str>, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = listen_addr.parse()?;
    let instances = Arc::new(DashMap::new());
    let (event_tx, _) = tokio::sync::broadcast::channel(1024);
    let process_mgr = Arc::new(ProcessManager::new(Arc::clone(&instances), event_tx.clone()));
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
        instances,
        process_mgr,
        state_mgr,
        event_tx,
        mcp_handler,
        api_key,
        prefix: prefix.to_string(),
        version: VERSION.to_string(),
        mid: "master-1".to_string(),
        alias: "nodepass-master".to_string(),
        hostname: "localhost".to_string(),
        start_time: Instant::now(),
    };

    let router = create_router(state);
    let listener = TcpListener::bind(bind_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
