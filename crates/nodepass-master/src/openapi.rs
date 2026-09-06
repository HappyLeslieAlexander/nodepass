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
  "security": [{{"ApiKeyAuth": []}}],
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
      "delete": {{
        "summary": "Delete instance",
        "responses": {{
          "204": {{"description": "Deleted"}}
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
    }}
  }},
  "components": {{
    "securitySchemes": {{
      "ApiKeyAuth": {{
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
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
