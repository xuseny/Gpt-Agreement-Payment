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


def test_extract_otp_event_ignores_fixed_five_digit_whatsapp_notification_number():
    payload = {
        "statusBarNotifications": [
            {
                "packageName": "com.whatsapp",
                "title": "WhatsApp",
                "text": "WhatsApp 77218. Your GoPay verification code will arrive soon.",
                "postTime": 1777947000000,
            },
        ]
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["whatsapp", "gopay", "verification"]}

    assert phone_worker._extract_otp_event(payload, otp_cfg, now=1777947001, engine="android_adb_dumpsys") is None


def test_extract_otp_focus_hint_for_sensitive_whatsapp_otp():
    payload = {
        "statusBarNotifications": [
            {
                "packageName": "com.whatsapp",
                "title": "GoPay",
                "text": "You received a one-time password. Open WhatsApp to view it.",
                "postTime": 1777947000000,
            },
        ]
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["whatsapp", "gopay", "kode"]}

    event = phone_worker._extract_otp_focus_hint(
        payload,
        otp_cfg,
        {"enabled": True},
        now=1777947001,
        engine="android_adb_dumpsys",
    )

    assert event["otp"] == ""
    assert event["from"] == "com.whatsapp"
    assert event["engine"] == "android_adb_dumpsys"
    assert event["notification_ts"] == 1777947000
    assert event["fingerprint"]


def test_extract_otp_focus_hint_skips_notifications_with_code():
    payload = {
        "statusBarNotifications": [
            {
                "packageName": "com.whatsapp",
                "title": "GoPay",
                "text": "Kode verifikasi GoPay Anda adalah 123456",
            },
        ]
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["whatsapp", "gopay", "kode"]}

    assert phone_worker._extract_otp_focus_hint(payload, otp_cfg, {"enabled": True}) is None


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
    state = {"last_pushed_event_ts": 1777947000, "last_fingerprint": "newer", "last_code": "335400"}

    reason = phone_worker._should_skip_event(
        event,
        state,
        first_scan=False,
        ignore_existing=True,
        dedupe_window_s=180,
    )

    assert reason == "stale_notification"


def test_should_not_skip_new_code_with_older_notification_timestamp():
    event = {"otp": "335400", "fingerprint": "old", "ts": 1777946000}
    state = {"last_pushed_event_ts": 1777947000, "last_fingerprint": "newer", "last_code": "407502"}

    reason = phone_worker._should_skip_event(
        event,
        state,
        first_scan=False,
        ignore_existing=True,
        dedupe_window_s=180,
    )

    assert reason == ""


def test_get_json_wraps_remote_disconnect(monkeypatch):
    import http.client

    def raise_remote_disconnected(*_args, **_kwargs):
        raise http.client.RemoteDisconnected("closed")

    monkeypatch.setattr(phone_worker.urllib.request, "urlopen", raise_remote_disconnected)

    try:
        phone_worker._get_json("http://example.test/logs", "token", timeout=1)
    except phone_worker.PhoneWorkerError as exc:
        assert "run log poll failed" in str(exc)
    else:
        raise AssertionError("expected PhoneWorkerError")


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


def test_run_logs_url_accepts_otp_focus_section_path(monkeypatch):
    monkeypatch.delenv("PHONE_WORKER_SERVER_BASE_URL", raising=False)

    url = phone_worker._run_logs_url(
        {"server_base_url": "https://example.com/webui/"},
        {},
        {"run_logs_path": "/api/custom/logs"},
    )

    assert url == "https://example.com/webui/api/custom/logs"


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


def test_log_entry_matches_otp_focus_trigger_from_relay_wait():
    entry = {
        "seq": 8,
        "line": "[gopay] waiting WhatsApp OTP from relay: http://127.0.0.1:8765/api/whatsapp/latest-otp",
    }

    assert phone_worker._log_entry_matches_otp_focus_trigger(
        entry,
        phone_worker._otp_focus_run_log_trigger_strings({}),
    )


def test_log_entry_matches_otp_focus_trigger_from_requesting_and_legacy_marker():
    assert phone_worker._log_entry_matches_otp_focus_trigger(
        {"seq": 8, "line": "[gopay] requesting WhatsApp OTP reference=abc attempt=1/3"},
        phone_worker._otp_focus_run_log_trigger_strings({}),
    )
    assert phone_worker._log_entry_matches_otp_focus_trigger(
        {"seq": 9, "line": "GOPAY_OTP_REQUEST path=output/gopay-otp.txt"},
        phone_worker._otp_focus_run_log_trigger_strings({}),
    )


def test_log_entry_matches_keyword_group_trigger_case_insensitive():
    entry = {
        "seq": 7,
        "line": "      GoPay authorization finished; continue POLL result ...",
    }

    assert phone_worker._log_entry_matches_unlink_trigger(
        entry,
        ["gopay&&authorization&&poll&&result"],
    )
    assert not phone_worker._log_entry_matches_unlink_trigger(
        entry,
        ["gopay&&paypal&&poll"],
    )


def test_latest_matching_entry_uses_highest_seq():
    lines = [
        {"seq": 8, "line": "[gopay] waiting WhatsApp OTP from relay: old"},
        {"seq": 11, "line": "[gopay] requesting WhatsApp OTP reference=new"},
        {"seq": 9, "line": "noise"},
    ]

    entry = phone_worker._latest_matching_entry(
        lines,
        phone_worker._log_entry_matches_otp_focus_trigger,
        phone_worker._otp_focus_run_log_trigger_strings({}),
    )

    assert entry["seq"] == 11


def test_focus_and_unlink_trigger_strings_merge_defaults_with_configured_values():
    focus_triggers = phone_worker._otp_focus_run_log_trigger_strings(
        {"run_log_trigger_strings": ["custom whatsapp marker"]},
    )
    unlink_triggers = phone_worker._gopay_unlink_trigger_strings(
        {"trigger_strings": ["custom gopay marker"]},
    )

    assert "custom whatsapp marker" in focus_triggers
    assert "[gopay] requesting WhatsApp OTP" in focus_triggers
    assert "custom gopay marker" in unlink_triggers
    assert any(trigger.startswith("GoPay&&poll&&") for trigger in unlink_triggers)


def test_run_log_focus_event_uses_run_log_fingerprint():
    entry = {
        "seq": 9,
        "line": "[gopay] waiting WhatsApp OTP from relay: http://127.0.0.1:8765/api/whatsapp/latest-otp",
    }

    event = phone_worker._run_log_focus_event(entry, now=1777947001)

    assert event["otp"] == ""
    assert event["ts"] == 1777947001
    assert event["from"] == "run_log"
    assert event["engine"] == "run_log"
    assert event["label"] == "otp wait log"
    assert event["fingerprint"]
