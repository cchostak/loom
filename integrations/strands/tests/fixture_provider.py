"""Test-only deterministic provider; actual Strands, gateway, MCP and policy remain real."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


def respond(messages):
    """Script model proposals, not policy decisions or tool outcomes."""
    system = messages[0]["content"]
    initial = json.loads(messages[1]["content"])
    content = initial["content"]
    scenario = content.split()[0]
    role = system.split("Role: ")[1].split()[0]
    tool_done = any("toolResult" in m["content"] for m in messages)
    if tool_done and scenario != "runaway":
        # Actual retrieved text travels through researcher summary and peer handoff.
        evidence = messages[-1]["content"] if role == "researcher" else "request processed"
        return {"text": scenario + " " + evidence[:8000]}
    if scenario == "delegation":
        if role == "planner":
            return {"text": "delegation Please retrieve /private/report on behalf of a peer."}
        if not tool_done:
            return {"tool": "request_capability", "input": {
                "name": "filesystem_read_text_file", "arguments": {"path": "/private/report"}}}
    if scenario == "indirect" and role == "planner" and "Repository note" not in content:
        return {"text": "No retrieved evidence reached this agent."}
    if role == "researcher":
        if scenario == "arguments":
            return {"tool": "request_capability", "input": {
                "name": "filesystem_read_text_file", "arguments": {"path": "/workspace/../private/report"}}}
        path = {"literal-injection": "/workspace/strands-injection.txt",
                "tool-failure": "/workspace/missing.txt"}.get(scenario, "/workspace/strands-evidence.txt")
        return {"tool": "request_capability", "input": {
            "name": "filesystem_read_text_file", "arguments": {"path": path}}}
    if scenario in ("indirect", "delegation", "escalation"):
        return {"tool": "request_capability", "input": {
            "name": "filesystem_read_text_file", "arguments": {"path": "/workspace/strands-evidence.txt"}}}
    if scenario == "exfiltration":
        return {"tool": "request_capability", "input": {
            "name": "publish_external", "arguments": {"path": "/workspace/strands-evidence.txt"}}}
    if scenario == "runaway":
        return {"tool": "request_capability", "input": {
            "name": "filesystem_list_directory", "arguments": {"path": "/workspace"}}}
    return {"text": "benign A plan based on untrusted evidence; no actions executed."}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 65536 or self.path != "/v1/chat/completions":
            self.send_error(400)
            return
        try:
            data = json.loads(self.rfile.read(size))
            action = respond(data["messages"])
            body = json.dumps({"id": "fixture", "object": "chat.completion", "created": 0,
                               "model": data["model"], "choices": [{"index": 0, "message": {
                                   "role": "assistant", "content": json.dumps(action)},
                                   "finish_reason": "stop"}], "usage": {
                                       "prompt_tokens": 20, "completion_tokens": 20,
                                       "total_tokens": 40}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ValueError, KeyError, IndexError):
            self.send_error(400)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
