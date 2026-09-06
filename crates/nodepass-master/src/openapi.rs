pub fn generate_openapi_spec(prefix: &str, version: &str) -> String {
    format!(
        r#"{{
  "openapi": "3.1.1",
  "info": {{
    "title": "NodePass API",
    "description": "API for managing NodePass server and client instances",
    "version": "{version}"
  }},
  "servers": [{{"url": "{prefix}"}}],
  "security": [
    {{"ApiKeyAuth": []}},
    {{"BearerAuth": []}}
  ],
  "paths": {{
    "/instances": {{
      "get": {{
        "summary": "List all instances",
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }},
      "post": {{
        "summary": "Create an instance",
        "responses": {{
          "201": {{"description": "Created"}}
        }}
      }}
    }},
    "/instances/{{id}}": {{
      "get": {{
        "summary": "Get instance detail",
        "responses": {{
          "200": {{"description": "Success"}},
          "404": {{"description": "Not Found"}}
        }}
      }},
      "patch": {{
        "summary": "Update instance alias or restart configuration",
        "responses": {{
          "200": {{"description": "Success"}},
          "404": {{"description": "Not Found"}}
        }}
      }},
      "delete": {{
        "summary": "Delete instance",
        "responses": {{
          "204": {{"description": "Deleted"}}
        }}
      }}
    }},
    "/instances/{{id}}/{{action}}": {{
      "post": {{
        "summary": "Control instance (start, stop, restart, reset)",
        "responses": {{
          "200": {{"description": "Action executed"}},
          "400": {{"description": "Invalid action"}},
          "404": {{"description": "Not Found"}}
        }}
      }}
    }},
    "/events": {{
      "get": {{
        "summary": "Server-Sent Events stream for instance updates",
        "responses": {{
          "200": {{
            "description": "SSE Event stream",
            "content": {{
              "text/event-stream": {{}}
            }}
          }}
        }}
      }}
    }},
    "/info": {{
      "get": {{
        "summary": "Get master system info",
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }}
    }},
    "/tcping": {{
      "get": {{
        "summary": "Ping TCP target",
        "responses": {{
          "200": {{"description": "Success"}}
        }}
      }}
    }},
    "/mcp": {{
      "post": {{
        "summary": "Model Context Protocol (MCP) JSON-RPC endpoint",
        "responses": {{
          "200": {{"description": "JSON-RPC response"}}
        }}
      }}
    }}
  }},
  "components": {{
    "securitySchemes": {{
      "ApiKeyAuth": {{
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
      }},
      "BearerAuth": {{
        "type": "http",
        "scheme": "bearer"
      }}
    }}
  }}
}}"#
    )
}

pub fn generate_swagger_ui_html(spec_json: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>NodePass API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => SwaggerUIBundle({{
      spec: {spec_json},
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout"
    }});
  </script>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_valid_json() {
        let spec_str = generate_openapi_spec("/api/v1", "1.1.1");
        let parsed: serde_json::Value = serde_json::from_str(&spec_str).expect("Valid JSON");
        assert_eq!(parsed["openapi"], "3.1.1");
        assert_eq!(parsed["info"]["version"], "1.1.1");
        assert!(parsed["paths"]["/instances/{id}/{action}"].is_object());
        assert!(parsed["paths"]["/events"].is_object());
        assert!(parsed["paths"]["/mcp"].is_object());
        assert!(parsed["components"]["securitySchemes"]["BearerAuth"].is_object());
    }
}
