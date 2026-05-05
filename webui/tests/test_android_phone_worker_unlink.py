from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "android_phone_worker",
    ROOT / "CTF-pay" / "android_phone_worker.py",
)
phone_worker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = phone_worker
SPEC.loader.exec_module(phone_worker)  # type: ignore[union-attr]


def test_run_configured_unlink_uses_subprocess_timeout(monkeypatch):
    captured = {}

    class Proc:
        returncode = 0
        stdout = '{"ok": true}'
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr(phone_worker.subprocess, "run", fake_run)

    rc = phone_worker._run_configured_unlink("config.json", "out-dir", timeout_s=9)

    assert rc == 0
    assert captured["cmd"][1].endswith("android_gopay_automation.py")
    assert captured["cmd"][-3:] == ["unlink", "--out", "out-dir"]
    assert captured["kwargs"]["timeout"] == 9


def test_run_configured_unlink_wraps_timeout(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise phone_worker.subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])

    monkeypatch.setattr(phone_worker.subprocess, "run", fake_run)

    try:
        phone_worker._run_configured_unlink("config.json", "out-dir", timeout_s=9)
    except phone_worker.PhoneWorkerError as exc:
        assert "timeout after 9.0s" in str(exc)
    else:
        raise AssertionError("expected PhoneWorkerError")
