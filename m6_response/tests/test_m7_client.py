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
