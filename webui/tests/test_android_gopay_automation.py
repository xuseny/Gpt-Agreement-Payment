from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "android_gopay_automation",
    ROOT / "CTF-pay" / "android_gopay_automation.py",
)
android_gopay = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = android_gopay
SPEC.loader.exec_module(android_gopay)  # type: ignore[union-attr]


def test_extract_otp_prefers_keyword_context():
    text = "Total IDR 39000. Kode verifikasi GoPay Anda adalah 445566. Jangan bagikan kode ini."

    assert android_gopay._extract_otp_from_text(text) == "445566"


def test_find_otp_in_notifications_filters_package_and_keywords():
    payload = {
        "statusBarNotifications": [
            {"packageName": "com.bank.app", "title": "Transfer", "text": "Kode 999999"},
            {
                "packageName": "com.whatsapp",
                "title": "WhatsApp",
                "text": "GoPay: kode verifikasi Anda 112233",
            },
        ],
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["gopay", "kode"]}

    assert android_gopay._find_otp_in_notifications(payload, otp_cfg) == "112233"


def test_find_otp_in_notifications_prefers_newest_timestamp():
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
        ],
    }
    otp_cfg = {"package_filters": ["com.whatsapp"], "keywords": ["gopay", "kode"]}

    assert android_gopay._find_otp_in_notifications(payload, otp_cfg) == "407502"


def test_config_example_uses_android_otp_command():
    cfg = json.loads((ROOT / "CTF-pay" / "config.android-gopay.example.json").read_text())

    assert cfg["gopay"]["otp"]["source"] == "command"
    assert "android_gopay_automation.py" in " ".join(cfg["gopay"]["otp"]["command"])
    assert cfg["android_automation"]["adb_serial"]
    assert cfg["phone_worker"]["notification_source"] == "adb"
    assert cfg["android_automation"]["otp"]["notification_source"] == "adb"


def test_proxy_pool_normalizes_authenticated_urls():
    proxy_cfg = {
        "enabled": True,
        "pool": [
            "http://user:pass@proxy.example:18898",
            {"host": "127.0.0.1", "port": 18899},
        ],
    }

    value = android_gopay._select_proxy_host_port(proxy_cfg, chooser=lambda items: items[0])

    assert value == "proxy.example:18898"


def test_dumpsys_notification_payload_keeps_matching_package():
    raw = """
    NotificationRecord(0x1: pkg=com.whatsapp user=UserHandle{0})
      android.title=GoPay
      android.text=Kode verifikasi GoPay Anda 778899
      mInterruptionTimeMs=1777951538509
    """

    payload = android_gopay._dumpsys_notification_payload(raw, {"package_filters": ["com.whatsapp"]})
    item = payload["statusBarNotifications"][0]

    assert android_gopay._find_otp_in_notifications(
        payload,
        {"package_filters": ["com.whatsapp"], "keywords": ["gopay", "kode"]},
    ) == "778899"
    assert item["postTime"] == 1777951538509


def test_step_runner_optional_tap_allows_missing_element(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = "<hierarchy><node text=\"Linked apps\" /></hierarchy>"

        def find_element(self, *_args):
            raise RuntimeError("missing")

    runner = android_gopay.StepRunner(Driver(), By)

    runner.run(
        [{"action": "tap_optional", "text": "Profile", "timeout_s": 0.01}],
        out_dir=tmp_path,
    )


def test_step_runner_back_if_text_any(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = "<hierarchy><node text=\"No apps linked to your GoPay\" /></hierarchy>"

        def __init__(self):
            self.back_calls = 0

        def back(self):
            self.back_calls += 1

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By)

    runner.run(
        [{
            "action": "back_if_text_any",
            "values": ["No apps linked to your GoPay"],
            "timeout_s": 0.01,
        }],
        out_dir=tmp_path,
    )

    assert driver.back_calls == 1
