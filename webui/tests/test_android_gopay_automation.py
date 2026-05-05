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


def test_config_example_uses_android_otp_command():
    cfg = json.loads((ROOT / "CTF-pay" / "config.android-gopay.example.json").read_text())

    assert cfg["gopay"]["otp"]["source"] == "command"
    assert "android_gopay_automation.py" in " ".join(cfg["gopay"]["otp"]["command"])
    assert cfg["android_automation"]["adb_serial"]
