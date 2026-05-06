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


def test_step_runner_text_contains_matches_content_description(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Element:
        def __init__(self):
            self.clicks = 0

        def click(self):
            self.clicks += 1

    class Driver:
        page_source = '<hierarchy><node content-desc="Profile" /></hierarchy>'

        def __init__(self, element):
            self.element = element
            self.selectors = []

        def find_element(self, by, selector):
            self.selectors.append((by, selector))
            if 'descriptionContains("Profile")' in selector:
                return self.element
            raise RuntimeError("missing")

    element = Element()
    driver = Driver(element)
    runner = android_gopay.StepRunner(driver, By)

    runner.run(
        [{"action": "tap", "text_contains": "Profile", "timeout_s": 0.01}],
        out_dir=tmp_path,
    )

    assert element.clicks == 1
    assert any('textContains("Profile")' in selector for _, selector in driver.selectors)
    assert any('descriptionContains("Profile")' in selector for _, selector in driver.selectors)


def test_step_runner_tap_row_uses_exact_linked_apps_row(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Element:
        def __init__(self, y):
            self.rect = {"x": 24, "y": y, "width": 312, "height": 48}
            self.clicks = 0

        def click(self):
            self.clicks += 1

    class Driver:
        page_source = """
        <hierarchy>
          <node text="Popular service permission" bounds="[24,180][336,228]" />
          <node text="Linked apps" bounds="[24,260][336,308]" />
        </hierarchy>
        """

        def __init__(self):
            self.linked = Element(260)
            self.popular = Element(180)
            self.selectors = []
            self.gestures = []

        def find_element(self, by, selector):
            self.selectors.append((by, selector))
            if 'text("Linked apps")' in selector:
                return self.linked
            if 'textContains("Linked apps")' in selector:
                return self.popular
            raise RuntimeError("missing")

        def get_window_size(self):
            return {"width": 360, "height": 800}

        def execute_script(self, script, payload):
            self.gestures.append((script, payload))

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    runner.run(
        [{"action": "tap_row", "text": "Linked apps", "timeout_s": 0.01}],
        out_dir=tmp_path,
    )

    assert driver.gestures == [("mobile: clickGesture", {"x": 180, "y": 284})]
    assert any('text("Linked apps")' in selector for _, selector in driver.selectors)
    assert not any('textContains("Linked apps")' in selector for _, selector in driver.selectors)


def test_step_runner_tap_source_text_uses_lower_non_heading_row(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = """
        <hierarchy>
          <node content-desc="Linked apps" heading="true" bounds="[168,168][484,240]" />
          <node content-desc="Linked apps" heading="false" bounds="[48,620][1032,760]" />
        </hierarchy>
        """

        def __init__(self):
            self.find_calls = 0
            self.gestures = []

        def get_window_size(self):
            return {"width": 1080, "height": 2400}

        def find_element(self, *_args):
            self.find_calls += 1
            raise RuntimeError("source tap should not use Appium find")

        def execute_script(self, script, payload):
            self.gestures.append((script, payload))

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    runner.run(
        [{
            "action": "tap_source_text",
            "text": "Linked apps",
            "exclude_heading": True,
            "min_y_ratio": 0.18,
            "row_center_x": True,
            "timeout_s": 0.01,
        }],
        out_dir=tmp_path,
    )

    assert driver.find_calls == 0
    assert driver.gestures == [("mobile: clickGesture", {"x": 540, "y": 690})]


def test_step_runner_tap_source_text_prefix_matches_clickable_multiline_row(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = """
        <hierarchy>
          <node content-desc="Account &amp; app settings" heading="true" clickable="false" bounds="[60,166][506,238]" />
          <node content-desc="Account &amp; app settings&#10;Control your app preferences, data, linked apps and more." heading="false" clickable="true" bounds="[48,741][1032,1005]" />
          <node content-desc="Popular service permission" heading="false" clickable="true" bounds="[48,1008][1032,1272]" />
        </hierarchy>
        """

        def __init__(self):
            self.find_calls = 0
            self.gestures = []

        def get_window_size(self):
            return {"width": 1080, "height": 2400}

        def find_element(self, *_args):
            self.find_calls += 1
            raise RuntimeError("source tap should not use Appium find")

        def execute_script(self, script, payload):
            self.gestures.append((script, payload))

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    runner.run(
        [{
            "action": "tap_source_text",
            "text": "Account & app settings",
            "match_mode": "prefix",
            "clickable_only": True,
            "exclude_heading": True,
            "min_y_ratio": 0.12,
            "row_center_x": True,
            "timeout_s": 0.01,
        }],
        out_dir=tmp_path,
    )

    assert driver.find_calls == 0
    assert driver.gestures == [("mobile: clickGesture", {"x": 540, "y": 873})]


def test_step_runner_tap_row_skips_appium_when_text_absent_from_source(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = """
        <hierarchy>
          <node content-desc="Popular service permission" />
          <node content-desc="No permission setting recorded" />
        </hierarchy>
        """

        def __init__(self):
            self.find_calls = 0

        def find_element(self, *_args):
            self.find_calls += 1
            raise RuntimeError("uia2 should not be called")

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    try:
        runner.run(
            [{"action": "tap_row", "text": "Linked apps", "timeout_s": 0.01}],
            out_dir=tmp_path,
        )
    except android_gopay.AndroidAutomationError as exc:
        assert "text not present in current page_source" in str(exc)
    else:
        raise AssertionError("expected AndroidAutomationError")

    assert driver.find_calls == 0
    assert (tmp_path / "step_01_error.xml").exists()


def test_step_runner_state_flow_advances_until_terminal(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Element:
        def __init__(self, driver, next_source):
            self.driver = driver
            self.next_source = next_source

        def click(self):
            self.driver.page_source = self.next_source

    class Driver:
        def __init__(self):
            self.page_source = '<hierarchy><node text="Profile" /></hierarchy>'

        def find_element(self, _by, selector):
            if "Profile" in selector:
                return Element(self, '<hierarchy><node text="Linked apps" /></hierarchy>')
            if "Linked apps" in selector:
                return Element(self, '<hierarchy><node text="No apps linked to your GoPay" /></hierarchy>')
            raise RuntimeError("missing")

        def save_screenshot(self, path):
            Path(path).write_bytes(b"png")

    runner = android_gopay.StepRunner(Driver(), By, log=lambda _msg: None)

    result = runner.run_states(
        [
            {
                "name": "done",
                "match_any": ["No apps linked to your GoPay"],
                "terminal": True,
            },
            {
                "name": "linked_apps",
                "match_any": ["Linked apps"],
                "steps": [{"action": "tap_row", "text": "Linked apps", "timeout_s": 0.01}],
            },
            {
                "name": "profile",
                "match_any": ["Profile"],
                "steps": [{"action": "tap", "text_contains": "Profile", "timeout_s": 0.01}],
            },
        ],
        out_dir=tmp_path,
        max_iterations=5,
        settle_s=0,
    )

    assert result["terminal_state"] == "done"
    assert result["history"] == ["profile", "linked_apps", "done"]


def test_step_runner_state_match_accepts_xml_escaped_text(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Element:
        def __init__(self, driver):
            self.driver = driver

        def click(self):
            self.driver.page_source = '<hierarchy><node content-desc="No apps linked to your GoPay" /></hierarchy>'

    class Driver:
        def __init__(self):
            self.page_source = (
                '<hierarchy><node pane-title="Account &amp; app settings" />'
                '<node content-desc="Linked apps" /></hierarchy>'
            )

        def find_element(self, _by, selector):
            if "Linked apps" in selector:
                return Element(self)
            raise RuntimeError("missing")

    runner = android_gopay.StepRunner(Driver(), By, log=lambda _msg: None)

    result = runner.run_states(
        [
            {
                "name": "linked_apps",
                "match_any": ["No apps linked to your GoPay"],
                "terminal": True,
            },
            {
                "name": "profile_settings",
                "match_any": ["Account & app settings"],
                "steps": [{"action": "tap_row", "text": "Linked apps", "timeout_s": 0.01}],
            },
        ],
        out_dir=tmp_path,
        max_iterations=3,
        settle_s=0,
    )

    assert result["history"] == ["profile_settings", "linked_apps"]


def test_step_runner_terminal_state_runs_cleanup_steps(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    class Driver:
        page_source = '<hierarchy><node text="No apps linked to your GoPay" /></hierarchy>'

        def __init__(self):
            self.back_calls = 0
            self.keycodes = []

        def back(self):
            self.back_calls += 1

        def press_keycode(self, keycode):
            self.keycodes.append(keycode)

    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    result = runner.run_states(
        [
            {
                "name": "already_unlinked",
                "match_any": ["No apps linked to your GoPay"],
                "terminal": True,
                "terminal_steps": [
                    {"action": "back"},
                    {"action": "press_keycode", "keycode": 3},
                ],
            },
        ],
        out_dir=tmp_path,
        max_iterations=1,
        settle_s=0,
    )

    assert result["terminal_state"] == "already_unlinked"
    assert driver.back_calls == 1
    assert driver.keycodes == [3]


def test_configured_gopay_unlink_state_flow_returns_to_account_settings(tmp_path):
    class By:
        ID = "id"
        XPATH = "xpath"
        ACCESSIBILITY_ID = "accessibility_id"
        ANDROID_UIAUTOMATOR = "android_uiautomator"

    sources = {
        "home": """
        <hierarchy>
          <node content-desc="Home" clickable="true" bounds="[0,2172][216,2340]" />
          <node content-desc="Finance" clickable="true" bounds="[216,2172][432,2340]" />
          <node content-desc="QRIS" clickable="true" bounds="[432,2172][648,2340]" />
          <node content-desc="History" clickable="true" bounds="[648,2172][864,2340]" />
          <node content-desc="Profile" clickable="true" bounds="[864,2172][1080,2340]" />
        </hierarchy>
        """,
        "account_safety": """
        <hierarchy>
          <node pane-title="Account &amp; safety" bounds="[0,0][1080,2364]" />
          <node content-desc="Account &amp; app settings&#10;Control your app preferences, data, linked apps and more." clickable="true" heading="false" bounds="[48,741][1032,1005]" />
        </hierarchy>
        """,
        "account_app_settings": """
        <hierarchy>
          <node pane-title="Account &amp; app settings" bounds="[0,0][1080,2364]" />
          <node content-desc="Popular service permission&#10;Manage information sharing permissions for each integrated app service." clickable="true" heading="false" bounds="[48,700][1032,940]" />
          <node content-desc="Unlink" clickable="false" bounds="[64,740][112,788]" />
          <node content-desc="Linked apps&#10;List of apps that you link to GoPay" clickable="true" heading="false" bounds="[48,940][1032,1120]" />
        </hierarchy>
        """,
        "linked_apps": """
        <hierarchy>
          <node pane-title="Linked apps" bounds="[0,0][1080,2364]" />
          <node content-desc="Linked apps" heading="true" clickable="false" bounds="[168,166][484,238]" />
          <node content-desc="OpenAI LLC&#10;Linked on May 6, 2026" clickable="false" bounds="[264,292][640,424]" />
          <node content-desc="Unlink" clickable="true" bounds="[766,290][990,396]" />
        </hierarchy>
        """,
        "unlink_confirm": """
        <hierarchy>
          <node pane-title="Linked apps" bounds="[0,0][1080,2364]" />
          <node content-desc="Linked apps" heading="true" clickable="false" bounds="[168,166][484,238]" />
          <node content-desc="Unlink" clickable="true" bounds="[766,290][990,396]" />
          <node content-desc="Unlink OpenAI LLC from GoPay?" clickable="false" bounds="[80,1750][1000,1840]" />
          <node content-desc="Once unlinked, you can’t use GoPay for transactions in OpenAI LLC." clickable="false" bounds="[80,1850][1000,1940]" />
          <node content-desc="Unlink" clickable="true" bounds="[48,2030][1032,2150]" />
        </hierarchy>
        """,
        "unlinked": """
        <hierarchy>
          <node pane-title="Linked apps" bounds="[0,0][1080,2364]" />
          <node content-desc="Successfully unlinked" clickable="false" bounds="[128,18][405,76]" />
          <node content-desc="No apps linked to your GoPay" clickable="false" bounds="[85,602][448,622]" />
        </hierarchy>
        """,
    }

    class Driver:
        def __init__(self):
            self.current = "home"
            self.page_source = sources[self.current]
            self.gestures = []
            self.back_calls = 0

        def get_window_size(self):
            return {"width": 1080, "height": 2400}

        def execute_script(self, script, payload):
            self.gestures.append((script, payload, self.current))
            if self.current == "home":
                self.current = "account_safety"
            elif self.current == "account_safety":
                self.current = "account_app_settings"
            elif self.current == "account_app_settings":
                self.current = "linked_apps"
            elif self.current == "linked_apps":
                self.current = "unlink_confirm"
            elif self.current == "unlink_confirm":
                self.current = "unlinked"
            self.page_source = sources[self.current]

        def back(self):
            self.back_calls += 1
            self.current = "account_app_settings"
            self.page_source = sources[self.current]

        def save_screenshot(self, path):
            Path(path).write_bytes(b"png")

    cfg = json.loads((ROOT / "CTF-pay" / "config.android-gopay.example.json").read_text())
    states = cfg["android_automation"]["gopay_unlink"]["states"]
    driver = Driver()
    runner = android_gopay.StepRunner(driver, By, log=lambda _msg: None)

    result = runner.run_states(states, out_dir=tmp_path, max_iterations=8, settle_s=0)

    assert result["terminal_state"] == "already_unlinked"
    assert result["history"] == [
        "home",
        "account_safety",
        "account_app_settings",
        "linked_apps",
        "unlink_confirm",
        "already_unlinked",
    ]
    assert driver.current == "account_app_settings"
    assert driver.back_calls == 1
