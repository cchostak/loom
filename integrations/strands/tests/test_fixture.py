"""Fixture proposals must depend on current-agent turns, not peer transcripts."""
import json

from tests.fixture_provider import respond


def messages(role, scenario, content=""):
    return [{"content": "Role: " + role}, {"content": json.dumps({
        "content": scenario + " " + content})}]


def test_peer_tool_result_is_not_current_agent_execution():
    result = respond(messages("planner", "indirect", 'Repository note [{"toolResult":{}}]'))
    assert result["tool"] == "request_capability"
    assert result["input"]["name"] == "read_text_file"


def test_indirect_requires_actual_retrieved_content():
    assert "tool" not in respond(messages("planner", "indirect"))


def test_current_turn_tool_result_ends_loop():
    prompt = messages("planner", "indirect", "Repository note")
    prompt.append({"content": '[{"toolResult": {"status":"error"}}]'})
    assert "text" in respond(prompt)


def test_runaway_keeps_requesting_after_tool_result():
    prompt = messages("operator", "runaway")
    prompt.append({"content": '[{"toolResult": {"status":"success"}}]'})
    assert respond(prompt)["tool"] == "list_directory"


def test_researcher_uses_native_mcp_tool():
    assert respond(messages("researcher", "benign"))["tool"] == "read_text_file"


def test_delegation_lower_to_higher_role():
    result = respond(messages("planner", "delegation"))
    assert "tool" not in result
    next_step = respond(messages("researcher", "delegation", result["text"]))
    assert next_step["input"]["path"] == "/private/report"
