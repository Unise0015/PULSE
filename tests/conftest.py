import socket

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    """Never contact live providers or mutate the user's history during tests."""
    def deny_network(*args, **kwargs):
        raise AssertionError("Live network access is forbidden in regression tests")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr("pulse.config.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("pulse.history.db.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("pulse.config.get_setting", lambda key, default="": str(default))
    from pulse.history.db import init_db
    from pulse.state import AppState
    monkeypatch.setattr(AppState, "OFFLINE_MODE", False)
    monkeypatch.setattr(AppState, "DEBUG_MODE", False)
    init_db()
