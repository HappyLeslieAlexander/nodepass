use crate::mcp::McpHandler;
use crate::openapi::{generate_openapi_spec, generate_swagger_ui_html};
use crate::process::ProcessManager;
use crate::state::StateManager;
use crate::sysinfo::get_master_info;
use crate::types::{Instance, InstanceEvent, MCPRequest, TCPingResult};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use futures_util::stream::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AppState {
    pub instances: Arc<DashMap<String, Instance>>,
    pub process_mgr: Arc<ProcessManager>,
    pub state_mgr: Arc<StateManager>,
    pub event_tx: broadcast::Sender<InstanceEvent>,
    pub mcp_handler: Arc<McpHandler>,
    pub api_key: String,
    pub prefix: String,
    pub version: String,
    pub mid: String,
    pub alias: Arc<parking_lot::RwLock<String>>,
    pub hostname: String,
    pub start_time: Instant,
    pub log_level: Option<String>,
    pub tls_code: Option<String>,
    pub crt_path: Option<String>,
    pub key_path: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let prefix = state.prefix.clone();

    Router::new()
        // OpenAPI spec & Swagger UI (Public)
        .route(
            &format!("{}/openapi.json", prefix),
            get(handle_openapi_spec),
        )
        .route(&format!("{}/docs", prefix), get(handle_swagger_docs))
        // REST endpoints (Protected)
        .route(
            &format!("{}/instances", prefix),
            get(handle_list_instances).post(handle_create_instance),
        )
        .route(
            &format!("{}/instances/:id", prefix),
            get(handle_get_instance)
                .patch(handle_patch_instance)
                .put(handle_put_instance)
                .delete(handle_delete_instance),
        )
        .route(
            &format!("{}/instances/:id/:action", prefix),
            post(handle_control_instance),
        )
        .route(&format!("{}/events", prefix), get(handle_sse_events))
        .route(
            &format!("{}/info", prefix),
            get(handle_info).post(handle_update_info),
        )
        .route(&format!("{}/tcping", prefix), get(handle_tcping))
        // MCP endpoint (POST /mcp or POST /api/mcp)
        .route("/mcp", post(handle_mcp))
        .route(
            &format!("{}/mcp", prefix.trim_end_matches("/v1")),
            post(handle_mcp),
        )
        .layer(cors)
        .with_state(state)
}

fn check_auth(headers: &HeaderMap, expected_key: &str) -> bool {
    if let Some(val) = headers
        .get("X-API-Key")
        .or_else(|| headers.get("x-api-key"))
    {
        if let Ok(str_val) = val.to_str() {
            if nodepass_core::crypto::constant_time_eq(str_val.as_bytes(), expected_key.as_bytes())
            {
                return true;
            }
        }
    }
    if let Some(val) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(str_val) = val.to_str() {
            if let Some(token) = str_val
                .strip_prefix("Bearer ")
                .or_else(|| str_val.strip_prefix("bearer "))
            {
                if nodepass_core::crypto::constant_time_eq(
                    token.trim().as_bytes(),
                    expected_key.as_bytes(),
                ) {
                    return true;
                }
            }
        }
    }
    false
}

async fn handle_openapi_spec(State(state): State<AppState>) -> impl IntoResponse {
    let spec = generate_openapi_spec(&state.prefix, &state.version);
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        spec,
    )
}

async fn handle_swagger_docs(State(state): State<AppState>) -> Html<String> {
    let spec = generate_openapi_spec(&state.prefix, &state.version);
    Html(generate_swagger_ui_html(&spec))
}

async fn handle_list_instances(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<Instance>>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let list: Vec<Instance> = state.instances.iter().map(|e| e.value().clone()).collect();
    Ok(Json(list))
}

pub fn enhance_url(
    instance_url: &str,
    instance_type: &str,
    log_level: Option<&str>,
    tls_code: Option<&str>,
    crt_path: Option<&str>,
    key_path: Option<&str>,
) -> String {
    let mut parsed_url = match url::Url::parse(instance_url) {
        Ok(u) => u,
        Err(_) => return instance_url.to_string(),
    };

    let mut query_pairs: Vec<(String, String)> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let has_key =
        |pairs: &[(String, String)], key: &str| -> bool { pairs.iter().any(|(k, _)| k == key) };

    if let Some(log) = log_level {
        if !log.is_empty() && !has_key(&query_pairs, "log") {
            query_pairs.push(("log".to_string(), log.to_string()));
        }
    }

    if instance_type == "server" {
        if let Some(tls) = tls_code {
            if tls != "0" {
                if !has_key(&query_pairs, "tls") {
                    query_pairs.push(("tls".to_string(), tls.to_string()));
                }
                if tls == "2" {
                    if let Some(crt) = crt_path {
                        if !crt.is_empty() && !has_key(&query_pairs, "crt") {
                            query_pairs.push(("crt".to_string(), crt.to_string()));
                        }
                    }
                    if let Some(key) = key_path {
                        if !key.is_empty() && !has_key(&query_pairs, "key") {
                            query_pairs.push(("key".to_string(), key.to_string()));
                        }
                    }
                }
            }
        }
        if !has_key(&query_pairs, "type") {
            query_pairs.push(("type".to_string(), "0".to_string()));
        }
    }

    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &query_pairs {
            serializer.append_pair(k, v);
        }
        parsed_url.set_query(Some(&serializer.finish()));
    }

    parsed_url.to_string()
}

pub fn generate_config_url(
    instance_url: &str,
    instance_type: &str,
    log_level: Option<&str>,
    tls_code: Option<&str>,
    crt_path: Option<&str>,
    key_path: Option<&str>,
) -> String {
    let mut parsed_url = match url::Url::parse(instance_url) {
        Ok(u) => u,
        Err(_) => return instance_url.to_string(),
    };

    let mut query_pairs: Vec<(String, String)> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let has_key =
        |pairs: &[(String, String)], key: &str| -> bool { pairs.iter().any(|(k, _)| k == key) };

    if let Some(log) = log_level {
        if !log.is_empty() && !has_key(&query_pairs, "log") {
            query_pairs.push(("log".to_string(), log.to_string()));
        }
    }

    if instance_type == "server" && tls_code.is_some_and(|t| t != "0") {
        if !has_key(&query_pairs, "tls") {
            if let Some(tls) = tls_code {
                query_pairs.push(("tls".to_string(), tls.to_string()));
            }
        }
        if tls_code == Some("2") {
            if let Some(crt) = crt_path {
                if !crt.is_empty() && !has_key(&query_pairs, "crt") {
                    query_pairs.push(("crt".to_string(), crt.to_string()));
                }
            }
            if let Some(key) = key_path {
                if !key.is_empty() && !has_key(&query_pairs, "key") {
                    query_pairs.push(("key".to_string(), key.to_string()));
                }
            }
        }
    }

    match instance_type {
        "client" => {
            if !has_key(&query_pairs, "dns") {
                query_pairs.push(("dns".to_string(), "5m0s".to_string()));
            }
            if !has_key(&query_pairs, "sni") {
                query_pairs.push(("sni".to_string(), "none".to_string()));
            }
            if !has_key(&query_pairs, "lbs") {
                query_pairs.push(("lbs".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "min") {
                query_pairs.push(("min".to_string(), "64".to_string()));
            }
            if !has_key(&query_pairs, "mode") {
                query_pairs.push(("mode".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "type") {
                query_pairs.push(("type".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "dial") {
                query_pairs.push(("dial".to_string(), "auto".to_string()));
            }
            if !has_key(&query_pairs, "read") {
                query_pairs.push(("read".to_string(), "0s".to_string()));
            }
            if !has_key(&query_pairs, "rate") {
                query_pairs.push(("rate".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "slot") {
                query_pairs.push(("slot".to_string(), "65536".to_string()));
            }
            if !has_key(&query_pairs, "proxy") {
                query_pairs.push(("proxy".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "block") {
                query_pairs.push(("block".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "notcp") {
                query_pairs.push(("notcp".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "noudp") {
                query_pairs.push(("noudp".to_string(), "0".to_string()));
            }
        }
        "server" => {
            if !has_key(&query_pairs, "dns") {
                query_pairs.push(("dns".to_string(), "5m0s".to_string()));
            }
            if !has_key(&query_pairs, "lbs") {
                query_pairs.push(("lbs".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "max") {
                query_pairs.push(("max".to_string(), "1024".to_string()));
            }
            if !has_key(&query_pairs, "mode") {
                query_pairs.push(("mode".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "dial") {
                query_pairs.push(("dial".to_string(), "auto".to_string()));
            }
            if !has_key(&query_pairs, "read") {
                query_pairs.push(("read".to_string(), "0s".to_string()));
            }
            if !has_key(&query_pairs, "rate") {
                query_pairs.push(("rate".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "slot") {
                query_pairs.push(("slot".to_string(), "65536".to_string()));
            }
            if !has_key(&query_pairs, "proxy") {
                query_pairs.push(("proxy".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "block") {
                query_pairs.push(("block".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "notcp") {
                query_pairs.push(("notcp".to_string(), "0".to_string()));
            }
            if !has_key(&query_pairs, "noudp") {
                query_pairs.push(("noudp".to_string(), "0".to_string()));
            }
        }
        _ => {}
    }

    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &query_pairs {
            serializer.append_pair(k, v);
        }
        parsed_url.set_query(Some(&serializer.finish()));
    }

    parsed_url.to_string()
}

#[derive(Deserialize)]
struct CreateInstanceReq {
    url: String,
    alias: Option<String>,
}

async fn handle_create_instance(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<CreateInstanceReq>,
) -> Result<(StatusCode, Json<Instance>), StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed = match url::Url::parse(&payload.url) {
        Ok(u) => u,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let scheme = parsed.scheme();
    if scheme != "client" && scheme != "server" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let enhanced = enhance_url(
        &payload.url,
        scheme,
        state.log_level.as_deref(),
        state.tls_code.as_deref(),
        state.crt_path.as_deref(),
        state.key_path.as_deref(),
    );

    let new_id = format!("{:08x}", rand::random::<u32>());
    let mut instance = Instance::new(
        new_id.clone(),
        payload.alias.unwrap_or_default(),
        scheme.to_string(),
        enhanced.clone(),
    );
    instance.config = generate_config_url(
        &enhanced,
        scheme,
        state.log_level.as_deref(),
        state.tls_code.as_deref(),
        state.crt_path.as_deref(),
        state.key_path.as_deref(),
    );

    state.instances.insert(new_id.clone(), instance.clone());
    let _ = state.state_mgr.save(&state.instances).await;
    let _ = state.process_mgr.start_instance(&new_id).await;

    let _ = state.event_tx.send(InstanceEvent {
        event_type: "create".to_string(),
        time: crate::types::now_timestamp_string(),
        instance: instance.clone(),
        logs: String::new(),
    });

    Ok((StatusCode::CREATED, Json(instance)))
}

async fn handle_get_instance(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Instance>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match state.instances.get(&id) {
        Some(inst) => Ok(Json(inst.value().clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize, Default)]
struct PatchMetaReq {
    peer: Option<crate::types::Peer>,
    tags: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize, Default)]
struct PatchInstanceReq {
    alias: Option<String>,
    action: Option<String>,
    restart: Option<bool>,
    meta: Option<PatchMetaReq>,
}

async fn handle_patch_instance(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<PatchInstanceReq>,
) -> Result<Json<Instance>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if id == crate::types::API_KEY_ID {
        if let Some(ref action) = payload.action {
            if action == "restart" {
                let new_key = format!("{:032x}", rand::random::<u128>());
                if let Some(mut inst) = state.instances.get_mut(&id) {
                    inst.url = new_key;
                    let snap = inst.clone();
                    drop(inst);
                    let _ = state.state_mgr.save(&state.instances).await;
                    let _ = state.event_tx.send(InstanceEvent {
                        event_type: "update".to_string(),
                        time: crate::types::now_timestamp_string(),
                        instance: snap.clone(),
                        logs: String::new(),
                    });
                    return Ok(Json(snap));
                }
            }
        }
        if let Some(inst) = state.instances.get(&id) {
            return Ok(Json(inst.value().clone()));
        }
        return Err(StatusCode::NOT_FOUND);
    }

    let mut entry = match state.instances.get_mut(&id) {
        Some(e) => e,
        None => return Err(StatusCode::NOT_FOUND),
    };

    if let Some(ref alias) = payload.alias {
        if alias.len() > 256 {
            return Err(StatusCode::BAD_REQUEST);
        }
        entry.alias = alias.clone();
    }

    if let Some(restart) = payload.restart {
        entry.restart = restart;
    }

    if let Some(meta_req) = payload.meta {
        if let Some(peer) = meta_req.peer {
            if peer.sid.len() > 256 || peer.peer_type.len() > 256 || peer.alias.len() > 256 {
                return Err(StatusCode::BAD_REQUEST);
            }
            entry.meta.peer = peer;
        }
        if let Some(tags) = meta_req.tags {
            for (k, v) in &tags {
                if k.len() > 256 || v.len() > 256 {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
            entry.meta.tags = tags;
        }
    }

    let action_opt = payload.action.clone();
    if let Some(ref action) = action_opt {
        if action == "reset" {
            entry.reset_metrics();
        } else if !["start", "stop", "restart"].contains(&action.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let snap = entry.clone();
    drop(entry);
    let _ = state.state_mgr.save(&state.instances).await;

    if let Some(action) = action_opt {
        match action.as_str() {
            "start" => {
                let _ = state.process_mgr.start_instance(&id).await;
            }
            "stop" => {
                state.process_mgr.stop_instance(&id).await;
            }
            "restart" => {
                let _ = state.process_mgr.restart_instance(&id).await;
            }
            _ => {}
        }
    }

    let _ = state.event_tx.send(InstanceEvent {
        event_type: "update".to_string(),
        time: crate::types::now_timestamp_string(),
        instance: snap.clone(),
        logs: String::new(),
    });

    Ok(Json(snap))
}

#[derive(Deserialize)]
struct PutInstanceReq {
    url: String,
}

async fn handle_put_instance(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<PutInstanceReq>,
) -> Result<Json<Instance>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if id == crate::types::API_KEY_ID {
        return Err(StatusCode::FORBIDDEN);
    }

    let parsed = match url::Url::parse(&payload.url) {
        Ok(u) => u,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let scheme = parsed.scheme();
    if scheme != "client" && scheme != "server" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let enhanced = enhance_url(
        &payload.url,
        scheme,
        state.log_level.as_deref(),
        state.tls_code.as_deref(),
        state.crt_path.as_deref(),
        state.key_path.as_deref(),
    );

    {
        let entry = match state.instances.get(&id) {
            Some(e) => e,
            None => return Err(StatusCode::NOT_FOUND),
        };

        if entry.url == enhanced {
            return Err(StatusCode::CONFLICT);
        }
    }

    state.process_mgr.stop_instance(&id).await;

    let snap = {
        let mut entry = match state.instances.get_mut(&id) {
            Some(e) => e,
            None => return Err(StatusCode::NOT_FOUND),
        };

        entry.url = enhanced;
        entry.instance_type = scheme.to_string();
        entry.config = generate_config_url(
            &entry.url,
            scheme,
            state.log_level.as_deref(),
            state.tls_code.as_deref(),
            state.crt_path.as_deref(),
            state.key_path.as_deref(),
        );
        entry.status = "stopped".to_string();

        entry.clone()
    };

    let _ = state.process_mgr.start_instance(&id).await;
    let _ = state.state_mgr.save(&state.instances).await;

    let _ = state.event_tx.send(InstanceEvent {
        event_type: "update".to_string(),
        time: crate::types::now_timestamp_string(),
        instance: snap.clone(),
        logs: String::new(),
    });

    Ok(Json(snap))
}

async fn handle_delete_instance(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if id == crate::types::API_KEY_ID {
        return Err(StatusCode::FORBIDDEN);
    }

    state.process_mgr.stop_instance(&id).await;
    if let Some((_, inst)) = state.instances.remove(&id) {
        let _ = state.event_tx.send(InstanceEvent {
            event_type: "delete".to_string(),
            time: crate::types::now_timestamp_string(),
            instance: inst,
            logs: String::new(),
        });
    }
    let _ = state.state_mgr.save(&state.instances).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn handle_control_instance(
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match action.as_str() {
        "start" => {
            let _ = state.process_mgr.start_instance(&id).await;
            Ok(StatusCode::OK)
        }
        "stop" => {
            state.process_mgr.stop_instance(&id).await;
            Ok(StatusCode::OK)
        }
        "restart" => {
            let _ = state.process_mgr.restart_instance(&id).await;
            Ok(StatusCode::OK)
        }
        "reset" => {
            if let Some(mut inst) = state.instances.get_mut(&id) {
                inst.reset_metrics();
            }
            let _ = state.state_mgr.save(&state.instances).await;
            Ok(StatusCode::OK)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_sse_events(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let rx = state.event_tx.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(evt) => {
                    if let Ok(data) = serde_json::to_string(&evt) {
                        return Some((Ok(Event::default().data(data)), rx));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn handle_info(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let current_alias = state.alias.read().clone();
    let info = get_master_info(
        &state.mid,
        &current_alias,
        &state.version,
        &state.hostname,
        state.log_level.as_deref().unwrap_or("info"),
        state.tls_code.as_deref().unwrap_or("0"),
        state.crt_path.as_deref().unwrap_or(""),
        state.key_path.as_deref().unwrap_or(""),
        state.start_time,
    );

    Ok(Json(info))
}

#[derive(Deserialize)]
struct UpdateInfoReq {
    alias: String,
}

async fn handle_update_info(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UpdateInfoReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if payload.alias.len() > 256 {
        return Err(StatusCode::BAD_REQUEST);
    }

    *state.alias.write() = payload.alias.clone();

    if let Some(mut api_key) = state.instances.get_mut(crate::types::API_KEY_ID) {
        api_key.alias = payload.alias.clone();
        drop(api_key);
        let _ = state.state_mgr.save(&state.instances).await;
    }

    let current_alias = state.alias.read().clone();
    let info = get_master_info(
        &state.mid,
        &current_alias,
        &state.version,
        &state.hostname,
        state.log_level.as_deref().unwrap_or("info"),
        state.tls_code.as_deref().unwrap_or("0"),
        state.crt_path.as_deref().unwrap_or(""),
        state.key_path.as_deref().unwrap_or(""),
        state.start_time,
    );

    Ok(Json(info))
}

#[derive(Deserialize)]
struct TCPingQuery {
    target: String,
}

pub fn check_tcping_target(target: &str) -> Result<(), String> {
    if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&target) {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    if ipv4.is_link_local()
                        || ipv4.is_broadcast()
                        || ipv4.is_unspecified()
                        || ipv4.is_loopback()
                    {
                        return Err(
                            "Access to loopback, link-local, or prohibited IP is blocked"
                                .to_string(),
                        );
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if ipv6.is_unspecified()
                        || ipv6.is_loopback()
                        || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                    {
                        return Err(
                            "Access to loopback, link-local, or prohibited IP is blocked"
                                .to_string(),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_tcping(
    headers: HeaderMap,
    Query(query): Query<TCPingQuery>,
    State(state): State<AppState>,
) -> Result<Json<TCPingResult>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Err(err) = check_tcping_target(&query.target) {
        return Ok(Json(TCPingResult {
            target: query.target,
            connected: false,
            latency: 0,
            error: Some(err),
        }));
    }

    let start = Instant::now();
    let res = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&query.target))
        .await
    {
        Ok(Ok(_)) => TCPingResult {
            target: query.target,
            connected: true,
            latency: start.elapsed().as_millis() as i64,
            error: None,
        },
        Ok(Err(e)) => TCPingResult {
            target: query.target,
            connected: false,
            latency: 0,
            error: Some(e.to_string()),
        },
        Err(_) => TCPingResult {
            target: query.target,
            connected: false,
            latency: 0,
            error: Some("Timeout".to_string()),
        },
    };

    Ok(Json(res))
}

async fn handle_mcp(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<MCPRequest>,
) -> Result<Json<crate::types::MCPResponse>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let resp = state.mcp_handler.handle_request(payload).await;
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhance_url_server_tls_mode2() {
        let raw = "server://:password@127.0.0.1:8080/127.0.0.1:80";
        let enhanced = enhance_url(
            raw,
            "server",
            Some("debug"),
            Some("2"),
            Some("/path/to/cert.pem"),
            Some("/path/to/key.pem"),
        );
        assert!(enhanced.contains("log=debug"));
        assert!(enhanced.contains("tls=2"));
        assert!(
            enhanced.contains("crt=%2Fpath%2Fto%2Fcert.pem")
                || enhanced.contains("crt=/path/to/cert.pem")
        );
        assert!(
            enhanced.contains("key=%2Fpath%2Fto%2Fkey.pem")
                || enhanced.contains("key=/path/to/key.pem")
        );
        assert!(enhanced.contains("type=0"));
    }

    #[test]
    fn test_generate_config_url_client_defaults() {
        let raw = "client://:password@127.0.0.1:8080/127.0.0.1:80";
        let config_url = generate_config_url(raw, "client", Some("info"), Some("0"), None, None);
        assert!(config_url.contains("dns=5m0s"));
        assert!(config_url.contains("sni=none"));
        assert!(config_url.contains("lbs=0"));
        assert!(config_url.contains("min=64"));
        assert!(config_url.contains("mode=0"));
        assert!(config_url.contains("type=0"));
        assert!(config_url.contains("slot=65536"));
        assert!(config_url.contains("log=info"));
    }

    #[test]
    fn test_generate_config_url_server_defaults() {
        let raw = "server://:password@127.0.0.1:8080/127.0.0.1:80";
        let config_url = generate_config_url(raw, "server", None, Some("0"), None, None);
        assert!(config_url.contains("dns=5m0s"));
        assert!(config_url.contains("lbs=0"));
        assert!(config_url.contains("max=1024"));
        assert!(config_url.contains("mode=0"));
        assert!(config_url.contains("slot=65536"));
    }
}
