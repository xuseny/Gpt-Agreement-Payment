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


def test_extract_otp_event_from_android_notification():
    payload = {
        "statusBarNotifications": [
            {"packageName": "com.bank", "title": "Bank", "text": "Kode 999999"},
            {
                "packageName": "com.whatsapp",
                "title": "GoPay",
                "text": "Kode verifikasi GoPay Anda adalah 123456",
                "postTime": 1777946000000,
            },
        ]
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["gopay", "kode"]}

    event = phone_worker._extract_otp_event(payload, otp_cfg, now=1777946001, engine="android_adb_dumpsys")

    assert event["otp"] == "123456"
    assert event["ts"] == 1777946000
    assert event["from"] == "com.whatsapp"
    assert event["engine"] == "android_adb_dumpsys"
    assert event["notification_ts"] == 1777946000
    assert event["fingerprint"]


def test_extract_otp_event_prefers_newest_notification_timestamp():
    payload = {
        "statusBarNotifications": [
            {
                "packageName": "com.whatsapp",
                "title": "GoPay",
                "text": "Kode verifikasi GoPay Anda adalah 407502",
                "postTime": 1777947000000,
            },
            {
                "packageName": "com.whatsapp",
                "title": "GoPay",
                "text": "Kode verifikasi GoPay Anda adalah 335400",
                "postTime": 1777946000000,
            },
        ]
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["gopay", "kode"]}

    event = phone_worker._extract_otp_event(payload, otp_cfg, now=1777947001, engine="android_adb_dumpsys")

    assert event["otp"] == "407502"
    assert event["notification_ts"] == 1777947000


def test_should_skip_first_existing_notification():
    event = {"otp": "123456", "fingerprint": "abc", "ts": 1000}

    reason = phone_worker._should_skip_event(
        event,
        {},
        first_scan=True,
        ignore_existing=True,
        dedupe_window_s=180,
    )

    assert reason == "initial_existing_notification"


def test_should_skip_older_notification_after_newer_push():
    event = {"otp": "335400", "fingerprint": "old", "ts": 1777946000}
    state = {"last_pushed_event_ts": 1777947000, "last_fingerprint": "newer"}

    reason = phone_worker._should_skip_event(
        event,
        state,
        first_scan=False,
        ignore_existing=True,
        dedupe_window_s=180,
    )

    assert reason == "stale_notification"


def test_push_delay_remaining_waits_after_notification_timestamp():
    event = {"otp": "123456", "ts": 1777946000, "notification_ts": 1777946000}

    assert phone_worker._push_delay_remaining(event, 20, now=1777946005) == 15
    assert phone_worker._push_delay_remaining(event, 20, now=1777946021) == 0


def test_push_url_joins_base_and_path(monkeypatch):
    monkeypatch.delenv("PHONE_WORKER_SERVER_BASE_URL", raising=False)

    url = phone_worker._push_url({
        "server_base_url": "https://example.com/webui/",
        "push_path": "/api/whatsapp/sidecar/state",
    })

    assert url == "https://example.com/webui/api/whatsapp/sidecar/state"


def test_run_logs_url_joins_default_path(monkeypatch):
    monkeypatch.delenv("PHONE_WORKER_SERVER_BASE_URL", raising=False)

    url = phone_worker._run_logs_url(
        {"server_base_url": "https://example.com/webui/"},
        {},
    )

    assert url == "https://example.com/webui/api/run/sidecar/logs"


def test_log_entry_matches_gopay_unlink_trigger():
    entry = {"seq": 7, "line": "      GoPay 授权 + 扣款完成，继续 poll 结果 ..."}

    assert phone_worker._log_entry_matches_unlink_trigger(
        entry,
        ["GoPay 授权 + 扣款完成"],
    )
    assert not phone_worker._log_entry_matches_unlink_trigger(
        entry,
        ["PayPal 授权完成"],
    )
