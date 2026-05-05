from __future__ import annotations

import importlib.util
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
        page_source = "<hierarchy />"

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
