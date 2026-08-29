# 🚀 Welcome to your Home IDE Powerhouse

This workspace is mounted directly into your containerized `code-server` instance and shared with `agentgateway`.

---

## 🛠️ Integrated Endpoints

| Service | Internal URL | External Host Port | Purpose |
| :--- | :--- | :--- | :--- |
| **Agentgateway LLM** | `http://agentgateway:8080/v1` | `http://localhost:8080/v1` | OpenAI-compatible proxy with guardrail filtering |
| **Agentgateway MCP** | `http://agentgateway:3000` | `http://localhost:3000` | Model Context Protocol server gateway |
| **Guardrail Proxy** | `http://guardrail-proxy:9090/validate` | `http://localhost:9090` | Intercepts prompts & blocks dangerous commands |
| **Jaeger UI** | `http://jaeger:16686` | `http://localhost:16686` | End-to-end distributed tracing UI |
| **OTel Collector** | `http://otel-collector:4317` | `localhost:4317` | OTLP gRPC ingestion pipeline |

---

## 🔒 Security & Guardrails

- **Prompt Interception**: Prompts containing destructive patterns (such as `sudo`, `rm -rf`, or fork bombs) are immediately rejected with `403 Forbidden`.
- **MCP Tool Authorization**: Evaluated via Common Expression Language (CEL). Only read-only filesystem tools (such as `read_text_file`, `list_directory`, and `search_files`) are permitted; all other tools default to `deny`.
- **Isolation**: All containers communicate inside the private `ide-net` bridge network.

---

## 💡 Quick Tips

1. **Configuring AI Assistant Extensions in code-server**:
   - Set the API Base URL to: `http://agentgateway:8080/v1`
   - Set the API Key to: your `OPENROUTER_API_KEY` (or dummy string if handled at gateway)
2. **Viewing Traces**:
   - Visit `http://localhost:16686` on your host machine to inspect spans generated for every LLM and tool invocation.
