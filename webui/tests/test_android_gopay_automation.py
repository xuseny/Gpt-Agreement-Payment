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


def test_extract_otp_accepts_english_hyphenated_whatsapp_code():
    text = "Your GoPay verification code is 123-456. Do not share this code with anyone."

    assert android_gopay._extract_otp_from_text(text) == "123456"


def test_extract_otp_ignores_fixed_five_digit_whatsapp_notification_number():
    text = "WhatsApp 77218. Your GoPay verification code will arrive soon."

    assert android_gopay._extract_otp_from_text(text) == ""


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
    assert cfg["phone_worker"]["otp_focus"]["focus_on_run_log"] is True
    assert "waiting WhatsApp OTP from relay" in cfg["phone_worker"]["otp_focus"]["run_log_trigger_strings"]
    assert cfg["android_automation"]["otp"]["notification_source"] == "adb"


def test_config_example_unlink_targets_linked_apps_from_profile_settings():
    cfg = json.loads((ROOT / "CTF-pay" / "config.android-gopay.example.json").read_text())
    states = {
        state["name"]: state
        for state in cfg["android_automation"]["gopay_unlink"]["states"]
    }

    profile_tab_step = states["profile_tab"]["steps"][0]
    assert profile_tab_step["action"] == "tap_row"
    assert "Account & app settings" in profile_tab_step["text_any"]
    assert profile_tab_step.get("text_contains") is None

    profile_settings = states["profile_settings"]
    assert profile_settings["match_all"] == ["Account & app settings", "Linked apps"]
    profile_settings_step = profile_settings["steps"][0]
    assert profile_settings_step["action"] == "tap_row"
    assert "Linked apps" in profile_settings_step["text_any"]
    assert profile_settings_step.get("text_contains") is None
    assert states["profile_settings_id"]["match_all"] == ["Pengaturan akun", "Aplikasi tertaut"]
    assert states["popular_service_permission"]["steps"][0]["action"] == "back"
    assert cfg["android_automation"]["gopay_unlink"]["exit_to_home_on_complete"] is True


def test_driver_wraps_appium_session_failure(monkeypatch):
    class WebDriver:
        @staticmethod
        def Remote(**_kwargs):
            raise RuntimeError("HTTPConnectionPool(host='127.0.0.1', port=4723): failed\ntrace line")

    class Options:
        def load_capabilities(self, _caps):
            pass

    monkeypatch.setattr(android_gopay, "_import_appium", lambda: (WebDriver, Options, object()))

    try:
        android_gopay._driver({"appium_server_url": "http://127.0.0.1:4723"})
    except android_gopay.AndroidAutomationError as exc:
        message = str(exc)
        assert "appium session failed at http://127.0.0.1:4723" in message
        assert "HTTPConnectionPool" in message
        assert "trace line" not in message
    else:
        raise AssertionError("expected AndroidAutomationError")


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


def test_configure_screen_awake_sends_adb_keepalive_commands(monkeypatch):
    calls = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run_adb(_adb_path, _serial, args, timeout=20.0):
        calls.append(args)
        return Proc()

    monkeypatch.setattr(android_gopay, "_run_adb", fake_run_adb)

    commands = android_gopay._configure_screen_awake({
        "screen": {
            "enabled": True,
            "screen_off_timeout_ms": 12345,
            "stay_on_while_plugged_in": 3,
        },
    })

    assert commands
    assert ["shell", "input", "keyevent", "224"] in calls
    assert ["shell", "svc", "power", "stayon", "true"] in calls
    assert ["shell", "settings", "put", "system", "screen_off_timeout", "12345"] in calls


def test_keep_screen_awake_wakes_and_dismisses_keyguard(monkeypatch):
    calls = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run_adb(_adb_path, _serial, args, timeout=20.0):
        calls.append(args)
        return Proc()

    monkeypatch.setattr(android_gopay, "_run_adb", fake_run_adb)

    assert android_gopay._keep_screen_awake({"screen": {"enabled": True}})
    assert ["shell", "input", "keyevent", "224"] in calls
    assert ["shell", "wm", "dismiss-keyguard"] in calls


def test_cmd_unlink_sends_adb_home_after_success(monkeypatch, tmp_path):
    calls = []

    cfg = {
        "android_automation": {
            "adb_path": "adb",
            "adb_serial": "serial-1",
            "gopay_unlink": {
                "package": "com.gojek.gopay",
                "states": [
                    {
                        "name": "done",
                        "default": True,
                        "terminal": True,
                    }
                ],
                "exit_to_home_on_complete": True,
            },
        }
    }

    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = '<hierarchy><node text="No apps linked to your GoPay" /></hierarchy>'

        def implicitly_wait(self, _seconds):
            pass

        def activate_app(self, _package):
            pass

        def save_screenshot(self, path):
            Path(path).write_bytes(b"png")

        def quit(self):
            pass

    class Args:
        config = "config.json"
        out = str(tmp_path)

    monkeypatch.setattr(android_gopay, "_load_json", lambda _path: cfg)
    monkeypatch.setattr(android_gopay, "_adb_connect", lambda _auto_cfg: None)
    monkeypatch.setattr(android_gopay, "_configure_screen_awake", lambda _auto_cfg: None)
    monkeypatch.setattr(android_gopay, "_set_android_proxy", lambda _auto_cfg: None)
    monkeypatch.setattr(android_gopay, "_keep_screen_awake", lambda _auto_cfg: None)
    monkeypatch.setattr(android_gopay, "_activate_app_adb", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(android_gopay, "_import_appium", lambda: (object(), object(), By))
    monkeypatch.setattr(android_gopay, "_driver", lambda *_args, **_kwargs: Driver())

    def fake_adb_best_effort(_auto_cfg, args, timeout=10.0):
        calls.append((args, timeout))
        return True

    monkeypatch.setattr(android_gopay, "_adb_best_effort", fake_adb_best_effort)

    assert android_gopay.cmd_unlink(Args()) == 0
    assert (["shell", "input", "keyevent", "3"], 5.0) in calls


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
