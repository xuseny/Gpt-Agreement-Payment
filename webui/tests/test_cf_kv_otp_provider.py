import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "CTF-reg" / "cf_kv_otp_provider.py"


def load_provider_module():
    spec = importlib.util.spec_from_file_location("cf_kv_otp_provider_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_wait_for_otp_accepts_recent_value_inside_default_grace():
    mod = load_provider_module()
    issued_after = 1777851989.0
    payload_ts = issued_after - 30.0
    provider = mod.CloudflareKVOtpProvider("token", "account", "kv")

    provider._kv_get = lambda key: {
        "otp": "123456",
        "ts": int(payload_ts * 1000),
        "from": "noreply@example.com",
    }
    provider._kv_delete = lambda key: None

    assert (
        provider.wait_for_otp(
            "User@Example.com",
            timeout=1,
            issued_after=issued_after,
        )
        == "123456"
    )


def test_wait_for_otp_still_rejects_value_outside_grace(monkeypatch):
    mod = load_provider_module()
    issued_after = 1777851989.0
    provider = mod.CloudflareKVOtpProvider(
        "token",
        "account",
        "kv",
        poll_interval_s=0.2,
        issued_after_grace_s=45.0,
    )
    provider._kv_get = lambda key: {
        "otp": "123456",
        "ts": int((issued_after - 60.0) * 1000),
        "from": "noreply@example.com",
    }

    class Clock:
        def __init__(self):
            self.now = issued_after

        def time(self):
            self.now += 0.25
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = Clock()
    monkeypatch.setattr(mod.time, "time", clock.time)
    monkeypatch.setattr(mod.time, "sleep", clock.sleep)

    with pytest.raises(TimeoutError):
        provider.wait_for_otp(
            "user@example.com",
            timeout=1,
            issued_after=issued_after,
        )


def test_issued_after_grace_can_be_configured_from_env(monkeypatch):
    mod = load_provider_module()
    monkeypatch.setenv("OTP_ISSUED_AFTER_GRACE_S", "60")

    provider = mod.CloudflareKVOtpProvider("token", "account", "kv")

    assert provider.issued_after_grace_s == 60.0


def test_wait_for_otp_deletes_known_html_color_false_positive():
    mod = load_provider_module()
    issued_after = 1777851989.0
    payloads = [
        {
            "otp": "353740",
            "ts": int(issued_after * 1000),
            "from": "noreply@example.com",
            "subject": "OpenAI",
        },
        {
            "otp": "246810",
            "ts": int(issued_after * 1000),
            "from": "noreply@example.com",
            "subject": "Your ChatGPT code is 246810",
        },
    ]
    deleted = []
    provider = mod.CloudflareKVOtpProvider(
        "token",
        "account",
        "kv",
        delete_after_read=False,
    )
    provider._kv_get = lambda key: payloads.pop(0)
    provider._kv_delete = lambda key: deleted.append(key)

    assert provider.wait_for_otp("user@example.com", timeout=1, issued_after=issued_after) == "246810"
    assert deleted == ["user@example.com"]


def test_wait_for_otp_allows_known_color_value_when_subject_confirms_it():
    mod = load_provider_module()
    issued_after = 1777851989.0
    provider = mod.CloudflareKVOtpProvider("token", "account", "kv")
    provider._kv_get = lambda key: {
        "otp": "353740",
        "ts": int(issued_after * 1000),
        "from": "noreply@example.com",
        "subject": "Your ChatGPT code is 353740",
    }
    provider._kv_delete = lambda key: None

    assert provider.wait_for_otp("user@example.com", timeout=1, issued_after=issued_after) == "353740"
