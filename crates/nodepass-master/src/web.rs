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
    pub alias: String,
    pub hostname: String,
    pub start_time: Instant,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let prefix = state.prefix.clone();

    Router::new()
        // OpenAPI spec & Swagger UI (Public)
        .route(&format!("{}/openapi.json", prefix), get(handle_openapi_spec))
        .route(&format!("{}/docs", prefix), get(handle_swagger_docs))
        // REST endpoints (Protected)
        .route(&format!("{}/instances", prefix), get(handle_list_instances).post(handle_create_instance))
        .route(&format!("{}/instances/:id", prefix), get(handle_get_instance).patch(handle_update_instance).delete(handle_delete_instance))
        .route(&format!("{}/instances/:id/:action", prefix), post(handle_control_instance))
        .route(&format!("{}/events", prefix), get(handle_sse_events))
        .route(&format!("{}/info", prefix), get(handle_info))
        .route(&format!("{}/tcping", prefix), get(handle_tcping))
        // MCP endpoint (POST /mcp or POST /api/mcp)
        .route("/mcp", post(handle_mcp))
        .route(&format!("{}/mcp", prefix.trim_end_matches("/v1")), post(handle_mcp))
        .layer(cors)
        .with_state(state)
}

fn check_auth(headers: &HeaderMap, expected_key: &str) -> bool {
    if let Some(val) = headers.get("X-API-Key").or_else(|| headers.get("x-api-key")) {
        if let Ok(str_val) = val.to_str() {
            if nodepass_core::crypto::constant_time_eq(str_val.as_bytes(), expected_key.as_bytes()) {
                return true;
            }
        }
    }
    if let Some(val) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(str_val) = val.to_str() {
            if let Some(token) = str_val.strip_prefix("Bearer ").or_else(|| str_val.strip_prefix("bearer ")) {
                if nodepass_core::crypto::constant_time_eq(token.trim().as_bytes(), expected_key.as_bytes()) {
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

    let new_id = format!("{:08x}", rand::random::<u32>());
    let instance = Instance::new(
        new_id.clone(),
        payload.alias.unwrap_or_default(),
        scheme.to_string(),
        payload.url,
    );

    state.instances.insert(new_id.clone(), instance.clone());
    let _ = state.state_mgr.save(&state.instances).await;
    let _ = state.process_mgr.start_instance(&new_id).await;

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

#[derive(Deserialize)]
struct UpdateInstanceReq {
    alias: Option<String>,
    restart: Option<bool>,
}

async fn handle_update_instance(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateInstanceReq>,
) -> Result<Json<Instance>, StatusCode> {
    if !check_auth(&headers, &state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut entry = match state.instances.get_mut(&id) {
        Some(e) => e,
        None => return Err(StatusCode::NOT_FOUND),
    };

    if let Some(alias) = payload.alias {
        entry.alias = alias;
    }
    if let Some(restart) = payload.restart {
        entry.restart = restart;
    }

    let snap = entry.clone();
    drop(entry);
    let _ = state.state_mgr.save(&state.instances).await;

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

    state.process_mgr.stop_instance(&id).await;
    state.instances.remove(&id);
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

    let info = get_master_info(
        &state.mid,
        &state.alias,
        &state.version,
        &state.hostname,
        "info",
        "0",
        "",
        "",
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
                    if ipv4.is_link_local() || ipv4.is_broadcast() || ipv4.is_unspecified() || ipv4.is_loopback() {
                        return Err("Access to loopback, link-local, or prohibited IP is blocked".to_string());
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if ipv6.is_unspecified() || ipv6.is_loopback() || ((ipv6.segments()[0] & 0xffc0) == 0xfe80) {
                        return Err("Access to loopback, link-local, or prohibited IP is blocked".to_string());
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
    let res = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&query.target)).await {
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
