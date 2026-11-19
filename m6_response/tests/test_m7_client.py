"""The M6 -> M7 client resolves its origin from the contract or the operator, never a literal."""
import os
from unittest import mock

from m6_response.m7_client.http_client import HttpM7Client
from m7_core.contract.loader import get_m7_base_url


def _env_without(*names):
    return {k: v for k, v in os.environ.items() if k not in names}


def test_base_url_defaults_to_the_published_server():
    with mock.patch.dict(os.environ, _env_without("M7_API_URL", "M6_MODULE_TOKEN"), clear=True):
        client = HttpM7Client(token="module-token")
    assert client.base_url == get_m7_base_url()


def test_operator_override_wins_over_the_contract_default():
    env = {**_env_without("M6_MODULE_TOKEN"), "M7_API_URL": "http://m7.internal:9000/"}
    with mock.patch.dict(os.environ, env, clear=True):
        client = HttpM7Client(token="module-token")
    assert client.base_url == "http://m7.internal:9000"


def test_explicit_argument_wins_over_the_environment():
    env = {**_env_without("M6_MODULE_TOKEN"), "M7_API_URL": "http://ignored:1234"}
    with mock.patch.dict(os.environ, env, clear=True):
        client = HttpM7Client(base_url="http://chosen:5678/", token="module-token")
    assert client.base_url == "http://chosen:5678"
    client.close()


def test_persistent_client_lifecycle_and_context_manager():
    with HttpM7Client(base_url="http://test.internal", token="test-tok") as client:
        sess = client.client
        assert not sess.is_closed
        assert client.client is sess  # Session reuse
    assert sess.is_closed


def test_client_retry_logic_on_connection_error():
    import httpx
    client = HttpM7Client(base_url="http://test.internal", token="test-tok", max_retries=2, backoff_factor=0.01)
    call_count = 0

    def mock_fetch(c):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise httpx.ConnectError("Connection refused")
        resp = httpx.Response(200, json={"analysis_id": "success"}, request=httpx.Request("GET", "http://test.internal"))
        return resp

    res = client._execute_with_retry(mock_fetch)
    assert res == {"analysis_id": "success"}
    assert call_count == 2
    client.close()

