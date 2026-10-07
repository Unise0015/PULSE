import json
import sqlite3
from unittest.mock import Mock

import httpx
import pytest

from pulse.domain.models import PackageInfo
from pulse.state import AppState
from pulse.vulnerability.osv_provider import OSVProvider


@pytest.fixture
def provider():
    provider = OSVProvider()
    provider.client.close()
    yield provider
    provider.client.close()


def set_response(provider, status=200, body=None):
    provider.client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, json=body)))


def package(name="requests"):
    return PackageInfo(name=name, version="2.0.0", ecosystem="PyPI")


@pytest.mark.parametrize("status,body", [(503, {}), (200, {}), (200, {"results": []}),
    (200, {"results": [None]}), (200, {"results": [{"vulns": "invalid"}]})])
def test_failures_are_not_negative_cache_entries(provider, status, body):
    set_response(provider, status, body)
    assert provider.lookup_packages([package()]) == []
    assert provider.warnings
    with sqlite3.connect(provider.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0] == 0
    set_response(provider, body={"results": [{}]})
    assert provider.lookup_packages([package()]) == []
    assert not provider.warnings
    with sqlite3.connect(provider.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0] == 1


def test_successful_empty_result_is_cached_and_progress_zero_advances(provider):
    set_response(provider, body={"results": [{}]})
    progress = Mock()
    provider.lookup_packages([package()], progress=progress, task_id=0)
    progress.advance.assert_any_call(0, 0.75)
    set_response(provider, status=503)
    assert provider.lookup_packages([package()]) == []
    assert not provider.warnings


def test_offline_cache_miss_never_sends_request(provider, monkeypatch):
    monkeypatch.setattr(AppState, "OFFLINE_MODE", True)
    provider.client = Mock()
    assert provider.lookup_packages([package()]) == []
    provider.client.post.assert_not_called()
    assert "offline" in provider.warnings[0]


def test_failed_chunk_preserves_successful_chunk_alignment(provider):
    count = 0
    def respond(request):
        nonlocal count
        count += 1
        if count == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"results": [{}]})
    provider.client = httpx.Client(transport=httpx.MockTransport(respond))
    packages = [package(f"fixture-{i}") for i in range(501)]
    provider.lookup_packages(packages)
    with sqlite3.connect(provider.db_path) as conn:
        rows = conn.execute("SELECT query_key FROM osv_cache").fetchall()
    assert rows == [("PyPI:fixture-500:2.0.0",)]
    assert provider.warnings
