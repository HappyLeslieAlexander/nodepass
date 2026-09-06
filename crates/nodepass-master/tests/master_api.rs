use axum::body::Body;
use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use nodepass_master::mcp::McpHandler;
use nodepass_master::process::ProcessManager;
use nodepass_master::state::StateManager;
use nodepass_master::web::{create_router, AppState};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::sync::broadcast;
use tower::ServiceExt;

fn create_test_app() -> (axum::Router, String) {
    let instances = Arc::new(DashMap::new());
    let (event_tx, _) = broadcast::channel(16);
    let process_mgr = Arc::new(ProcessManager::new(Arc::clone(&instances), event_tx.clone()));
    let temp_file = NamedTempFile::new().unwrap();
    let state_mgr = Arc::new(StateManager::new(temp_file.path()));

    let api_key = "test-secret-key".to_string();
    let prefix = "/api/v1".to_string();
    let version = "1.1.1".to_string();

    let mcp_handler = Arc::new(McpHandler::new(
        Arc::clone(&instances),
        Arc::clone(&process_mgr),
        Arc::clone(&state_mgr),
        version.clone(),
        "test-mid".to_string(),
        "test-alias".to_string(),
        "localhost".to_string(),
        Instant::now(),
    ));

    let state = AppState {
        instances,
        process_mgr,
        state_mgr,
        event_tx,
        mcp_handler,
        api_key: api_key.clone(),
        prefix,
        version,
        mid: "test-mid".to_string(),
        alias: "test-alias".to_string(),
        hostname: "localhost".to_string(),
        start_time: Instant::now(),
    };

    (create_router(state), api_key)
}

#[tokio::test]
async fn test_rest_api_auth_and_crud() {
    let (app, api_key) = create_test_app();

    // 1. Unauthorized request
    let req = Request::builder()
        .uri("/api/v1/instances")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Authorized GET instances (initially empty)
    let req = Request::builder()
        .uri("/api/v1/instances")
        .method("GET")
        .header("X-API-Key", &api_key)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Create instance
    let create_body = json!({
        "url": "client://:pass@127.0.0.1:8080/127.0.0.1:80?mode=1",
        "alias": "web-tunnel"
    });
    let req = Request::builder()
        .uri("/api/v1/instances")
        .method("POST")
        .header("X-API-Key", &api_key)
        .header("Content-Type", "application/json")
        .body(Body::from(create_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let created_inst: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let inst_id = created_inst["id"].as_str().unwrap();
    assert_eq!(created_inst["alias"], "web-tunnel");

    // 4. Get instance by ID
    let req = Request::builder()
        .uri(format!("/api/v1/instances/{}", inst_id))
        .method("GET")
        .header("X-API-Key", &api_key)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. OpenAPI spec (Public, no auth)
    let req = Request::builder()
        .uri("/api/v1/openapi.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Swagger UI HTML (Public, no auth)
    let req = Request::builder()
        .uri("/api/v1/docs")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mcp_api_via_http() {
    let (app, api_key) = create_test_app();

    // 1. MCP initialize call
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize"
    });
    let req = Request::builder()
        .uri("/mcp")
        .method("POST")
        .header("X-API-Key", &api_key)
        .header("Content-Type", "application/json")
        .body(Body::from(init_req.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp_json["result"]["serverInfo"]["name"], "Master");

    // 2. MCP tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    let req = Request::builder()
        .uri("/mcp")
        .method("POST")
        .header("X-API-Key", &api_key)
        .header("Content-Type", "application/json")
        .body(Body::from(list_req.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let tools = resp_json["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 19);
}
