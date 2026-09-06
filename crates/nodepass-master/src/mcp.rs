use crate::process::ProcessManager;
use crate::state::StateManager;
use crate::sysinfo::get_master_info;
use crate::types::{Instance, MCPRequest, MCPResponse, TCPingResult, MCP_VERSION};
use dashmap::DashMap;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub struct McpHandler {
    instances: Arc<DashMap<String, Instance>>,
    process_mgr: Arc<ProcessManager>,
    state_mgr: Arc<StateManager>,
    version: String,
    mid: String,
    alias: Arc<parking_lot::RwLock<String>>,
    hostname: String,
    start_time: Instant,
}

impl McpHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instances: Arc<DashMap<String, Instance>>,
        process_mgr: Arc<ProcessManager>,
        state_mgr: Arc<StateManager>,
        version: String,
        mid: String,
        alias: String,
        hostname: String,
        start_time: Instant,
    ) -> Self {
        Self {
            instances,
            process_mgr,
            state_mgr,
            version,
            mid,
            alias: Arc::new(parking_lot::RwLock::new(alias)),
            hostname,
            start_time,
        }
    }

    pub async fn handle_request(&self, req: MCPRequest) -> MCPResponse {
        if req.jsonrpc != "2.0" {
            return MCPResponse::error(req.id, -32600, "Invalid Request: jsonrpc must be 2.0", None);
        }

        match req.method.as_str() {
            "initialize" => self.handle_initialize(req.id).await,
            "tools/list" => self.handle_tools_list(req.id).await,
            "tools/call" => self.handle_tools_call(req.id, req.params).await,
            _ => MCPResponse::error(req.id, -32601, format!("Method not found: {}", req.method), None),
        }
    }

    async fn handle_initialize(&self, id: Option<Value>) -> MCPResponse {
        let result = json!({
            "protocolVersion": MCP_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "Master",
                "version": self.version
            }
        });
        MCPResponse::success(id, result)
    }

    async fn handle_tools_list(&self, id: Option<Value>) -> MCPResponse {
        let tools = json!([
            {
                "name": "list_instances",
                "description": "List all instances",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "get_instance",
                "description": "Get details of a specific instance",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string", "description": "Instance ID" } },
                    "required": ["id"]
                }
            },
            {
                "name": "create_instance",
                "description": "Create a new instance with structured configuration",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "alias": { "type": "string" },
                        "type": { "type": "string", "enum": ["client", "server"] },
                        "tunnel_address": { "type": "string" },
                        "tunnel_port": { "type": "string" },
                        "target_address": { "type": "string" },
                        "target_port": { "type": "string" },
                        "password": { "type": "string" }
                    },
                    "required": ["type", "tunnel_port", "target_port"]
                }
            },
            {
                "name": "update_instance",
                "description": "Update instance metadata (alias, restart policy, peer, tags)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "alias": { "type": "string" },
                        "restart": { "type": "boolean" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "control_instance",
                "description": "Control instance state (start, stop, restart, reset)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "action": { "type": "string", "enum": ["start", "stop", "restart", "reset"] }
                    },
                    "required": ["id", "action"]
                }
            },
            {
                "name": "set_instance_basic",
                "description": "Set instance basic configuration",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_security",
                "description": "Set instance security and encryption settings",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "password": { "type": "string" }, "tls": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_connection",
                "description": "Set instance connection pool settings",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "mode": { "type": "string" }, "min": { "type": "string" }, "max": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_network",
                "description": "Set instance network tuning parameters",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "dns": { "type": "string" }, "rate": { "type": "string" }, "slot": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_protocol",
                "description": "Set instance protocol control settings",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "proxy": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_traffic",
                "description": "Set instance traffic control and load balancing",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "block": { "type": "string" }, "lbs": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "set_instance_advanced",
                "description": "Set instance advanced/custom parameters",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" }, "parameters": { "type": "object" } },
                    "required": ["id", "parameters"]
                }
            },
            {
                "name": "get_instance_config",
                "description": "Get instance configuration",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "delete_instance",
                "description": "Delete an instance",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "export_instances",
                "description": "Export all instances configuration",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "import_instances",
                "description": "Import instances configuration",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "tcping_target",
                "description": "Test TCP connectivity",
                "inputSchema": {
                    "type": "object",
                    "properties": { "target": { "type": "string" } },
                    "required": ["target"]
                }
            },
            {
                "name": "get_master_info",
                "description": "Get master information",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "update_master_info",
                "description": "Update master alias (server name or label)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "alias": { "type": "string", "description": "New alias for master" }
                    },
                    "required": ["alias"]
                }
            }
        ]);

        MCPResponse::success(id, json!({ "tools": tools }))
    }

    async fn handle_tools_call(&self, id: Option<Value>, params_opt: Option<Value>) -> MCPResponse {
        let params = match params_opt {
            Some(p) => p,
            None => return MCPResponse::error(id, -32602, "Missing params", None),
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return MCPResponse::error(id, -32602, "Missing tool name", None),
        };

        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        let text_output = match tool_name {
            "list_instances" => {
                let list: Vec<Instance> = self.instances.iter().map(|e| e.value().clone()).collect();
                serde_json::to_string_pretty(&list).unwrap_or_default()
            }
            "get_instance" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                match self.instances.get(inst_id) {
                    Some(inst) => serde_json::to_string_pretty(inst.value()).unwrap_or_default(),
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                }
            }
            "create_instance" => {
                let inst_type = args.get("type").and_then(|v| v.as_str()).unwrap_or("client");
                let alias = args.get("alias").and_then(|v| v.as_str()).unwrap_or("");
                let tunnel_port = args.get("tunnel_port").and_then(|v| v.as_str()).unwrap_or("8080");
                let target_port = args.get("target_port").and_then(|v| v.as_str()).unwrap_or("80");
                let tunnel_addr = args.get("tunnel_address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                let target_addr = args.get("target_address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                let pwd = args.get("password").and_then(|v| v.as_str()).unwrap_or("");

                let url_str = if pwd.is_empty() {
                    format!("{}://{}:{}/{}:{}", inst_type, tunnel_addr, tunnel_port, target_addr, target_port)
                } else {
                    format!("{}://:{}@{}:{}/{}:{}", inst_type, pwd, tunnel_addr, tunnel_port, target_addr, target_port)
                };

                let new_id = format!("{:08x}", rand::random::<u32>());
                let inst = Instance::new(new_id.clone(), alias.to_string(), inst_type.to_string(), url_str);
                self.instances.insert(new_id.clone(), inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Created instance {}", new_id)
            }
            "update_instance" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Some(alias) = args.get("alias").and_then(|v| v.as_str()) {
                    inst.alias = alias.to_string();
                }
                if let Some(restart) = args.get("restart").and_then(|v| v.as_bool()) {
                    inst.restart = restart;
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Updated instance {}", inst_id)
            }
            "control_instance" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let action = args.get("action").and_then(|v| v.as_str()).unwrap_or_default();
                match action {
                    "start" => {
                        let _ = self.process_mgr.start_instance(inst_id).await;
                        format!("Started instance {}", inst_id)
                    }
                    "stop" => {
                        self.process_mgr.stop_instance(inst_id).await;
                        format!("Stopped instance {}", inst_id)
                    }
                    "restart" => {
                        let _ = self.process_mgr.restart_instance(inst_id).await;
                        format!("Restarted instance {}", inst_id)
                    }
                    "reset" => {
                        if let Some(mut inst) = self.instances.get_mut(inst_id) {
                            inst.reset_metrics();
                        }
                        let _ = self.state_mgr.save(&self.instances).await;
                        format!("Reset metrics for instance {}", inst_id)
                    }
                    _ => return MCPResponse::error(id, -32602, format!("Invalid action {}", action), None),
                }
            }
            "set_instance_basic" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["type", "tunnel_address", "tunnel_port", "target_address", "target_port", "targets", "log"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set basic configuration for instance {}", inst_id)
            }
            "set_instance_security" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["password", "tls", "crt", "key", "sni"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set security configuration for instance {}", inst_id)
            }
            "set_instance_connection" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["mode", "min", "max", "pool"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set connection configuration for instance {}", inst_id)
            }
            "set_instance_network" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["dns", "rate", "slot", "read", "dial"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set network configuration for instance {}", inst_id)
            }
            "set_instance_protocol" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["proxy", "notcp", "noudp"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set protocol configuration for instance {}", inst_id)
            }
            "set_instance_traffic" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                for field in &["block", "lbs"] {
                    if let Some(v) = args.get(*field).and_then(|v| v.as_str()) {
                        updates.insert(field.to_string(), v.to_string());
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set traffic configuration for instance {}", inst_id)
            }
            "set_instance_advanced" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let mut updates = std::collections::HashMap::new();
                if let Some(params_obj) = args.get("parameters").and_then(|v| v.as_object()) {
                    for (k, v) in params_obj {
                        let val_str = if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            v.to_string()
                        };
                        updates.insert(k.clone(), val_str);
                    }
                }
                let mut inst = match self.instances.get_mut(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                if let Err(e) = update_instance_url(&mut inst, updates) {
                    return MCPResponse::error(id, -32602, e, None);
                }
                drop(inst);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Set advanced parameters for instance {}", inst_id)
            }
            "get_instance_config" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                let inst = match self.instances.get(inst_id) {
                    Some(i) => i,
                    None => return MCPResponse::error(id, -32602, format!("Instance {} not found", inst_id), None),
                };
                let parsed_url = match url::Url::parse(&inst.url) {
                    Ok(u) => u,
                    Err(e) => return MCPResponse::error(id, -32602, format!("Failed to parse instance URL: {}", e), None),
                };
                let query_map: std::collections::HashMap<String, String> =
                    parsed_url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                let path = parsed_url.path().trim_start_matches('/');
                let mut target_addr = "";
                let mut target_port = "";
                if path.contains(':') {
                    let parts: Vec<&str> = path.split(':').collect();
                    target_addr = parts[0];
                    if parts.len() > 1 { target_port = parts[1]; }
                }
                let config_json = json!({
                    "id": inst_id,
                    "type": parsed_url.scheme(),
                    "password": parsed_url.password().unwrap_or(parsed_url.username()),
                    "tunnel_address": parsed_url.host_str().unwrap_or_default(),
                    "tunnel_port": parsed_url.port().map(|p| p.to_string()).unwrap_or_default(),
                    "target_address": target_addr,
                    "target_port": target_port,
                    "targets": path,
                    "parameters": query_map,
                });
                serde_json::to_string_pretty(&config_json).unwrap_or_default()
            }
            "delete_instance" => {
                let inst_id = args.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                self.process_mgr.stop_instance(inst_id).await;
                self.instances.remove(inst_id);
                let _ = self.state_mgr.save(&self.instances).await;
                format!("Deleted instance {}", inst_id)
            }
            "export_instances" => {
                let _ = self.state_mgr.save(&self.instances).await;
                "Exported instances to state file".to_string()
            }
            "import_instances" => {
                let _ = self.state_mgr.load(&self.instances);
                "Imported instances from state file".to_string()
            }
            "tcping_target" => {
                let target = args.get("target").and_then(|v| v.as_str()).unwrap_or_default();
                if let Err(err) = crate::web::check_tcping_target(target) {
                    let res = TCPingResult {
                        target: target.to_string(),
                        connected: false,
                        latency: 0,
                        error: Some(err),
                    };
                    serde_json::to_string_pretty(&res).unwrap_or_default()
                } else {
                    let start = Instant::now();
                    let res = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await {
                        Ok(Ok(_)) => TCPingResult {
                            target: target.to_string(),
                            connected: true,
                            latency: start.elapsed().as_millis() as i64,
                            error: None,
                        },
                        Ok(Err(e)) => TCPingResult {
                            target: target.to_string(),
                            connected: false,
                            latency: 0,
                            error: Some(e.to_string()),
                        },
                        Err(_) => TCPingResult {
                            target: target.to_string(),
                            connected: false,
                            latency: 0,
                            error: Some("Timeout".to_string()),
                        },
                    };
                    serde_json::to_string_pretty(&res).unwrap_or_default()
                }
            }
            "get_master_info" => {
                let alias = self.alias.read().clone();
                let info = get_master_info(
                    &self.mid,
                    &alias,
                    &self.version,
                    &self.hostname,
                    "info",
                    "0",
                    "",
                    "",
                    self.start_time,
                );
                serde_json::to_string_pretty(&info).unwrap_or_default()
            }
            "update_master_info" => {
                let new_alias = args.get("alias").and_then(|v| v.as_str()).unwrap_or_default();
                if new_alias.is_empty() {
                    return MCPResponse::error(id, -32602, "alias is required", None);
                }
                *self.alias.write() = new_alias.to_string();
                format!("Master alias updated to: {}", new_alias)
            }
            _ => return MCPResponse::error(id, -32601, format!("Method not found: {}", tool_name), None),
        };

        let result = json!({
            "content": [
                {
                    "type": "text",
                    "text": text_output
                }
            ]
        });

        MCPResponse::success(id, result)
    }
}

fn update_instance_url(inst: &mut Instance, updates: std::collections::HashMap<String, String>) -> Result<(), String> {
    let mut parsed_url = url::Url::parse(&inst.url).map_err(|e| format!("Invalid URL: {}", e))?;

    if let Some(t) = updates.get("type") {
        parsed_url.set_scheme(t).map_err(|_| "Invalid scheme".to_string())?;
        inst.instance_type = t.clone();
    }
    if let Some(addr) = updates.get("tunnel_address") {
        parsed_url.set_host(Some(addr)).map_err(|e| format!("Invalid host: {}", e))?;
    }
    if let Some(port_str) = updates.get("tunnel_port") {
        let port: u16 = port_str.parse().map_err(|_| "Invalid port".to_string())?;
        parsed_url.set_port(Some(port)).map_err(|_| "Failed to set port".to_string())?;
    }
    if let Some(pwd) = updates.get("password") {
        if pwd.is_empty() {
            let _ = parsed_url.set_password(None);
            let _ = parsed_url.set_username("");
        } else {
            let _ = parsed_url.set_password(Some(pwd));
        }
    }
    if let Some(targets) = updates.get("targets") {
        let path = if targets.starts_with('/') { targets.clone() } else { format!("/{}", targets) };
        parsed_url.set_path(&path);
    } else if updates.contains_key("target_address") || updates.contains_key("target_port") {
        let current_path = parsed_url.path().trim_start_matches('/');
        let mut cur_addr = "127.0.0.1";
        let mut cur_port = "80";
        if current_path.contains(':') {
            let parts: Vec<&str> = current_path.split(':').collect();
            cur_addr = parts[0];
            if parts.len() > 1 { cur_port = parts[1]; }
        }
        let new_addr = updates.get("target_address").map(|s| s.as_str()).unwrap_or(cur_addr);
        let new_port = updates.get("target_port").map(|s| s.as_str()).unwrap_or(cur_port);
        parsed_url.set_path(&format!("{}:{}", new_addr, new_port));
    }

    let special_keys = [
        "type", "tunnel_address", "tunnel_port", "target_address", "target_port", "targets", "password",
    ];
    let mut query_map: std::collections::BTreeMap<String, String> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for (k, v) in updates {
        if !special_keys.contains(&k.as_str()) {
            if v.is_empty() {
                query_map.remove(&k);
            } else {
                query_map.insert(k, v);
            }
        }
    }

    if query_map.is_empty() {
        parsed_url.set_query(None);
    } else {
        let mut pairs = parsed_url.query_pairs_mut();
        pairs.clear();
        for (k, v) in &query_map {
            pairs.append_pair(k, v);
        }
    }

    inst.url = parsed_url.to_string();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_mcp_initialize_and_tools_list() {
        let instances = Arc::new(DashMap::new());
        let (tx, _) = broadcast::channel(16);
        let process_mgr = Arc::new(ProcessManager::new(Arc::clone(&instances), tx));
        let temp_file = NamedTempFile::new().unwrap();
        let state_mgr = Arc::new(StateManager::new(temp_file.path()));

        let handler = McpHandler::new(
            instances,
            process_mgr,
            state_mgr,
            "1.1.1".to_string(),
            "master-id".to_string(),
            "my-master".to_string(),
            "localhost".to_string(),
            Instant::now(),
        );

        // 1. Initialize
        let init_req = MCPRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };
        let init_resp = handler.handle_request(init_req).await;
        assert_eq!(init_resp.jsonrpc, "2.0");
        assert!(init_resp.error.is_none());
        let res = init_resp.result.unwrap();
        assert_eq!(res["serverInfo"]["name"], "Master");

        // 2. Tools list
        let list_req = MCPRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/list".to_string(),
            params: None,
        };
        let list_resp = handler.handle_request(list_req).await;
        assert!(list_resp.error.is_none());
        let tools = list_resp.result.unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 19);

        // 3. Call update_master_info
        let update_req = MCPRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "update_master_info",
                "arguments": {
                    "alias": "new-master-alias"
                }
            })),
        };
        let update_resp = handler.handle_request(update_req).await;
        assert!(update_resp.error.is_none());
    }
}
