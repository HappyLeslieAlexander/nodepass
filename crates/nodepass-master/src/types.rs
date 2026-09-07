use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

pub const API_KEY_ID: &str = "00000000";
pub const DEFAULT_API_PATH: &str = "/api";
pub const OPENAPI_VERSION: &str = "v1";
pub const NEXT_MCP_VERSION: &str = "mcp";
pub const MCP_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    #[serde(default)]
    pub alias: String,
    #[serde(rename = "type")]
    pub instance_type: String,
    pub status: String,
    pub url: String,
    #[serde(default)]
    pub config: String,
    #[serde(default = "default_true")]
    pub restart: bool,
    #[serde(default)]
    pub meta: Meta,
    #[serde(default)]
    pub mode: i32,
    #[serde(default)]
    pub ping: i32,
    #[serde(default)]
    pub pool: i32,
    #[serde(default)]
    pub tcps: i32,
    #[serde(default)]
    pub udps: i32,
    #[serde(default)]
    pub tcprx: u64,
    #[serde(default)]
    pub tcptx: u64,
    #[serde(default)]
    pub udprx: u64,
    #[serde(default)]
    pub udptx: u64,
    #[serde(skip)]
    pub tcp_rx_base: u64,
    #[serde(skip)]
    pub tcp_tx_base: u64,
    #[serde(skip)]
    pub udp_rx_base: u64,
    #[serde(skip)]
    pub udp_tx_base: u64,
    #[serde(skip)]
    pub tcp_rx_reset: u64,
    #[serde(skip)]
    pub tcp_tx_reset: u64,
    #[serde(skip)]
    pub udp_rx_reset: u64,
    #[serde(skip)]
    pub udp_tx_reset: u64,
    #[serde(skip)]
    pub last_checkpoint: Option<Instant>,
    #[serde(skip)]
    pub deleted: bool,
}

fn default_true() -> bool {
    true
}

impl Instance {
    pub fn new(id: String, alias: String, instance_type: String, url: String) -> Self {
        Self {
            id,
            alias,
            instance_type,
            status: "stopped".to_string(),
            url,
            config: String::new(),
            restart: true,
            meta: Meta::default(),
            mode: 0,
            ping: 0,
            pool: 0,
            tcps: 0,
            udps: 0,
            tcprx: 0,
            tcptx: 0,
            udprx: 0,
            udptx: 0,
            tcp_rx_base: 0,
            tcp_tx_base: 0,
            udp_rx_base: 0,
            udp_tx_base: 0,
            tcp_rx_reset: 0,
            tcp_tx_reset: 0,
            udp_rx_reset: 0,
            udp_tx_reset: 0,
            last_checkpoint: None,
            deleted: false,
        }
    }

    pub fn reset_metrics(&mut self) {
        self.tcp_rx_reset += self.tcprx.saturating_sub(self.tcp_rx_base);
        self.tcp_tx_reset += self.tcptx.saturating_sub(self.tcp_tx_base);
        self.udp_rx_reset += self.udprx.saturating_sub(self.udp_rx_base);
        self.udp_tx_reset += self.udptx.saturating_sub(self.udp_tx_base);
        self.tcprx = 0;
        self.tcptx = 0;
        self.udprx = 0;
        self.udptx = 0;
        self.tcp_rx_base = 0;
        self.tcp_tx_base = 0;
        self.udp_rx_base = 0;
        self.udp_tx_base = 0;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub peer: Peer,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Peer {
    #[serde(default)]
    pub sid: String,
    #[serde(rename = "type", default)]
    pub peer_type: String,
    #[serde(default)]
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub time: String,
    pub instance: Instance,
    #[serde(default)]
    pub logs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub cpu: i32,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub netrx: u64,
    pub nettx: u64,
    pub diskr: u64,
    pub diskw: u64,
    pub sysup: u64,
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            cpu: -1,
            mem_total: 0,
            mem_used: 0,
            swap_total: 0,
            swap_used: 0,
            netrx: 0,
            nettx: 0,
            diskr: 0,
            diskw: 0,
            sysup: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCPingResult {
    pub target: String,
    pub connected: bool,
    pub latency: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<MCPError>,
}

impl MCPResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(
        id: Option<serde_json::Value>,
        code: i32,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(MCPError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

pub fn now_timestamp_string() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}
