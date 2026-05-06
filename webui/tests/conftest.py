import pytest
from fastapi.testclient import TestClient
from webui.server import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBUI_DATA_DIR", str(tmp_path))
    app = create_app()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_runner():
    yield
    import webui.backend.runner as r
    r._proc = None
    r._started_at = None
    r._ended_at = None
    r._exit_code = None
    r._cmd = None
    r._mode = None
    r._log_lines = []
    r._seq_counter = 0
    r._continuous_enabled = False
    r._continuous_params = None
    r._continuous_restart_attempt = 0
    r._continuous_restart_at = None
    r._continuous_last_error = ""
    r._continuous_worker = None
