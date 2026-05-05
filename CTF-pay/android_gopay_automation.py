#!/usr/bin/env python3
"""Android/Appium helper for GoPay OTP capture and configurable UI flows.

The script is intentionally data-driven. It can read Android notifications for
WhatsApp OTPs, dump the current UI tree for selector discovery, and execute a
configured GoPay unlink flow after the selectors have been recorded from the
user-owned emulator/device.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


DEFAULT_CONFIG = Path(__file__).with_name("config.android-gopay.example.json")
DEFAULT_CODE_REGEX = r"(?<!\d)(\d{6})(?!\d)"
DEFAULT_KEYWORDS = ("gopay", "gojek", "whatsapp", "otp", "kode", "verifikasi", "verification", "code")
_OTP_CONTEXT_RE = r"otp|one[-\s]*time|password|verification|verify|code|kode|verifikasi|gopay|gojek"


class AndroidAutomationError(RuntimeError):
    pass


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise AndroidAutomationError(f"config root must be an object: {path}")
    return data


def _section(cfg: dict, name: str) -> dict:
    value = cfg.get(name) or {}
    if not isinstance(value, dict):
        raise AndroidAutomationError(f"{name} must be an object")
    return value


def _automation_cfg(cfg: dict) -> dict:
    return _section(cfg, "android_automation")


def _candidate_digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def _code_regex_accepts(digits: str, code_regex: str = DEFAULT_CODE_REGEX) -> bool:
    if not digits:
        return False
    pattern = code_regex or DEFAULT_CODE_REGEX
    try:
        return bool(re.fullmatch(pattern, digits))
    except re.error:
        return bool(re.fullmatch(DEFAULT_CODE_REGEX, digits))


def _extract_otp_from_text(text: str, code_regex: str = DEFAULT_CODE_REGEX) -> str:
    if not text:
        return ""
    patterns = [
        code_regex or DEFAULT_CODE_REGEX,
        r"(?<!\d)((?:\d[\s.-]?){6})(?!\d)",
        rf"(?:{_OTP_CONTEXT_RE})[^\d]{{0,100}}((?:\d[\s.-]?){{6}})(?!\d)",
        rf"(?<!\d)((?:\d[\s.-]?){{6}})[^\n\r]{{0,100}}(?:{_OTP_CONTEXT_RE})",
    ]
    for pattern in patterns:
        try:
            matches = list(re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL))
        except re.error:
            continue
        for match in reversed(matches):
            groups = match.groups() or (match.group(0),)
            for group in reversed(groups):
                digits = _candidate_digits(group)
                if _code_regex_accepts(digits, code_regex=code_regex):
                    return digits
    return ""


def _iter_strings(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, (str, int, float, bool)):
        yield str(value)
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def _notification_text(item: Any) -> str:
    if not isinstance(item, dict):
        return " ".join(_iter_strings(item))
    preferred = []
    for key in (
        "packageName",
        "appName",
        "title",
        "text",
        "bigText",
        "tickerText",
        "subText",
        "summaryText",
        "template",
    ):
        if key in item:
            preferred.append(str(item.get(key) or ""))
    extras = item.get("extras")
    if extras is not None:
        preferred.extend(_iter_strings(extras))
    if not preferred:
        preferred.extend(_iter_strings(item))
    return " ".join(p for p in preferred if p)


def _notification_package(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("packageName", "package", "appPackage"):
        if item.get(key):
            return str(item[key])
    return ""


def _coerce_epoch(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        ts = float(value)
    except Exception:
        return None
    if ts <= 0:
        return None
    if ts > 10_000_000_000:
        ts = ts / 1000.0
    return ts


def _notification_epoch(item: Any) -> Optional[float]:
    if not isinstance(item, dict):
        return None
    for key in ("postTime", "post_time", "when", "timestamp", "ts", "time"):
        ts = _coerce_epoch(item.get(key))
        if ts is not None:
            return ts
    nested = item.get("notification")
    if isinstance(nested, dict):
        for key in ("postTime", "when", "timestamp"):
            ts = _coerce_epoch(nested.get(key))
            if ts is not None:
                return ts
    return None


def _iter_notifications(payload: Any) -> Iterable[dict]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(payload, dict):
        return
    for key in ("statusBarNotifications", "notifications", "value"):
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item


def _matches_filters(text: str, package_name: str, otp_cfg: dict) -> bool:
    package_filters = [str(x).lower() for x in otp_cfg.get("package_filters", []) if str(x).strip()]
    if package_filters and not any(p in package_name.lower() for p in package_filters):
        return False
    keywords = [str(x).lower() for x in otp_cfg.get("keywords", DEFAULT_KEYWORDS) if str(x).strip()]
    if keywords and not any(k in text.lower() for k in keywords):
        return False
    return True


def _find_otp_in_notifications(payload: Any, otp_cfg: dict) -> str:
    code_regex = str(otp_cfg.get("code_regex") or DEFAULT_CODE_REGEX)
    candidates = []
    for index, item in enumerate(list(_iter_notifications(payload))):
        text = _notification_text(item)
        package_name = _notification_package(item)
        if not _matches_filters(text, package_name, otp_cfg):
            continue
        code = _extract_otp_from_text(text, code_regex=code_regex)
        if code:
            notification_ts = _notification_epoch(item)
            candidates.append((notification_ts is not None, notification_ts or 0.0, index, code))
    if not candidates:
        return ""
    return max(candidates, key=lambda item: (item[0], item[1], item[2]))[3]


def _import_appium():
    try:
        from appium import webdriver  # type: ignore
        from appium.options.android import UiAutomator2Options  # type: ignore
        from appium.webdriver.common.appiumby import AppiumBy  # type: ignore
    except Exception as exc:
        raise AndroidAutomationError(
            "missing Appium Python client; install with: pip install Appium-Python-Client"
        ) from exc
    return webdriver, UiAutomator2Options, AppiumBy


def _run_adb(adb_path: str, serial: str, args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    cmd = [adb_path or "adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _dumpsys_notification_payload(raw: str, otp_cfg: Optional[dict] = None) -> dict:
    text = raw or ""
    package_filters = []
    if isinstance(otp_cfg, dict):
        package_filters = [str(x).lower() for x in otp_cfg.get("package_filters", []) if str(x).strip()]
    blocks = re.split(r"\n(?=\s*(?:NotificationRecord|Notification\(|StatusBarNotification\())", text)
    items = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        pkg = ""
        match = re.search(r"\bpkg=([A-Za-z0-9_.]+)", block)
        if not match:
            match = re.search(r"\b(?:package|packageName|opPkg)=([A-Za-z0-9_.]+)", block)
        if match:
            pkg = match.group(1)
        elif package_filters:
            for candidate in package_filters:
                if candidate in block.lower():
                    pkg = candidate
                    break
        timestamp = None
        for pattern in (
            r"\bmInterruptionTimeMs=(\d{10,})",
            r"\bpostTime=(\d{10,})",
            r"\bwhen=(\d{10,})",
        ):
            ts_match = re.search(pattern, block)
            if ts_match:
                timestamp = int(ts_match.group(1))
                break
        item = {
            "packageName": pkg,
            "title": "adb dumpsys notification",
            "text": block,
            "source": "adb_dumpsys_notification",
        }
        if timestamp is not None:
            item["postTime"] = timestamp
        items.append(item)
    if not items:
        pkg = ""
        for candidate in package_filters:
            if candidate in text.lower():
                pkg = candidate
                break
        items.append({
            "packageName": pkg,
            "title": "adb dumpsys notification",
            "text": text,
            "source": "adb_dumpsys_notification",
        })
    return {"statusBarNotifications": items}


def _adb_notification_payload(auto_cfg: dict, otp_cfg: Optional[dict] = None) -> dict:
    proc = _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        ["shell", "dumpsys", "notification", "--noredact"],
        timeout=20,
    )
    if proc.returncode != 0:
        proc = _run_adb(
            str(auto_cfg.get("adb_path") or "adb"),
            str(auto_cfg.get("adb_serial") or ""),
            ["shell", "dumpsys", "notification"],
            timeout=20,
        )
    if proc.returncode != 0:
        raise AndroidAutomationError(f"adb dumpsys notification failed: {proc.stderr or proc.stdout}")
    return _dumpsys_notification_payload(proc.stdout or "", otp_cfg)


def _proxy_host_port(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("http_proxy", "host_port", "value"):
            if value.get(key):
                return _proxy_host_port(value.get(key))
        if value.get("url"):
            return _proxy_host_port(value.get("url"))
        host = str(value.get("host") or "").strip()
        port = str(value.get("port") or "").strip()
        if host and port:
            return f"{host}:{port}"
        return ""
    raw = str(value or "").strip()
    if not raw:
        return ""
    m = re.match(r"^[a-zA-Z0-9+.-]+://(?:[^@/]+@)?([^/:]+):(\d+)", raw)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    return raw


def _select_proxy_host_port(proxy_cfg: dict, *, chooser=random.choice) -> str:
    pool = proxy_cfg.get("pool") or proxy_cfg.get("proxies") or []
    if isinstance(pool, list):
        candidates = [_proxy_host_port(item) for item in pool]
        candidates = [item for item in candidates if item]
        if candidates:
            return str(chooser(candidates))
    return _proxy_host_port(
        proxy_cfg.get("http_proxy")
        or proxy_cfg.get("host_port")
        or proxy_cfg.get("url")
    )


def _adb_connect(auto_cfg: dict) -> None:
    serial = str(auto_cfg.get("adb_serial") or "").strip()
    if not serial or ":" not in serial:
        return
    adb_path = str(auto_cfg.get("adb_path") or "adb")
    proc = subprocess.run(
        [adb_path, "connect", serial],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        raise AndroidAutomationError(f"adb connect failed: {proc.stderr or proc.stdout}")


def _set_android_proxy(auto_cfg: dict) -> None:
    proxy_cfg = auto_cfg.get("proxy") or {}
    if not isinstance(proxy_cfg, dict) or not proxy_cfg.get("enabled"):
        return
    value = _select_proxy_host_port(proxy_cfg)
    if not value:
        raise AndroidAutomationError("android_automation.proxy requires http_proxy/host_port or url")
    proc = _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        ["shell", "settings", "put", "global", "http_proxy", value],
    )
    if proc.returncode != 0:
        raise AndroidAutomationError(f"set android proxy failed: {proc.stderr or proc.stdout}")


def _clear_android_proxy(auto_cfg: dict) -> None:
    proxy_cfg = auto_cfg.get("proxy") or {}
    if not isinstance(proxy_cfg, dict) or not proxy_cfg.get("clear_on_exit"):
        return
    _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        ["shell", "settings", "delete", "global", "http_proxy"],
    )
    _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        ["shell", "settings", "delete", "global", "global_http_proxy_host"],
    )
    _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        ["shell", "settings", "delete", "global", "global_http_proxy_port"],
    )


def _screen_cfg(auto_cfg: dict) -> dict:
    value = auto_cfg.get("screen") or auto_cfg.get("keep_awake") or {}
    if value is True:
        return {"enabled": True}
    if not isinstance(value, dict):
        return {}
    return value


def _screen_awake_enabled(auto_cfg: dict) -> bool:
    cfg = _screen_cfg(auto_cfg)
    return bool(cfg.get("enabled") or cfg.get("keep_awake"))


def _adb_best_effort(auto_cfg: dict, args: list[str], *, timeout: float = 10.0) -> bool:
    try:
        proc = _run_adb(
            str(auto_cfg.get("adb_path") or "adb"),
            str(auto_cfg.get("adb_serial") or ""),
            args,
            timeout=timeout,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _configure_screen_awake(auto_cfg: dict) -> list[list[str]]:
    """Best-effort screen keep-awake setup.

    Some Android builds do not expose a UI "never sleep" option. These ADB
    commands keep the device awake while the worker is running and periodically
    wake it back up if OEM power management still dims the display.
    """
    if not _screen_awake_enabled(auto_cfg):
        return []
    cfg = _screen_cfg(auto_cfg)
    timeout_ms = int(cfg.get("screen_off_timeout_ms") or cfg.get("timeout_ms") or 2_147_483_647)
    stay_on_value = str(cfg.get("stay_on_while_plugged_in") or cfg.get("stay_on_value") or "3")
    commands: list[list[str]] = []
    if cfg.get("wake_on_start", True):
        commands.append(["shell", "input", "keyevent", str(cfg.get("wake_keycode") or 224)])
    if cfg.get("dismiss_keyguard", True):
        commands.append(["shell", "wm", "dismiss-keyguard"])
    if cfg.get("set_stay_on_while_plugged", True):
        commands.append(["shell", "svc", "power", "stayon", "true"])
        commands.append(["shell", "settings", "put", "global", "stay_on_while_plugged_in", stay_on_value])
    if cfg.get("set_screen_off_timeout", True):
        commands.append(["shell", "settings", "put", "system", "screen_off_timeout", str(timeout_ms)])
    for command in commands:
        _adb_best_effort(auto_cfg, command)
    return commands


def _keep_screen_awake(auto_cfg: dict) -> bool:
    if not _screen_awake_enabled(auto_cfg):
        return False
    cfg = _screen_cfg(auto_cfg)
    ok = _adb_best_effort(
        auto_cfg,
        ["shell", "input", "keyevent", str(cfg.get("wake_keycode") or 224)],
        timeout=5.0,
    )
    if cfg.get("dismiss_keyguard", True):
        _adb_best_effort(auto_cfg, ["shell", "wm", "dismiss-keyguard"], timeout=5.0)
    return ok


def _app_package(app_cfg: Optional[dict], default: str = "") -> str:
    if not isinstance(app_cfg, dict):
        return default
    return str(app_cfg.get("package") or app_cfg.get("app_package") or default or "").strip()


def _app_activity(app_cfg: Optional[dict], default: str = "") -> str:
    if not isinstance(app_cfg, dict):
        return default
    return str(app_cfg.get("activity") or app_cfg.get("app_activity") or default or "").strip()


def _activate_app_adb(auto_cfg: dict, app_cfg: dict, *, label: str = "app") -> None:
    package = _app_package(app_cfg)
    if not package:
        return
    activity = _app_activity(app_cfg)
    if activity:
        component = f"{package}/{activity}"
        args = ["shell", "am", "start", "-n", component]
    else:
        args = ["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]
    proc = _run_adb(
        str(auto_cfg.get("adb_path") or "adb"),
        str(auto_cfg.get("adb_serial") or ""),
        args,
        timeout=float(app_cfg.get("start_timeout_s") or 20),
    )
    if proc.returncode != 0:
        raise AndroidAutomationError(f"activate {label} failed: {proc.stderr or proc.stdout}")
    delay_s = float(app_cfg.get("start_wait_s") or app_cfg.get("activate_wait_s") or 1.5)
    if delay_s > 0:
        time.sleep(delay_s)


def _activate_app_driver(driver: Any, app_cfg: dict, *, label: str = "app") -> None:
    package = _app_package(app_cfg)
    if not package:
        return
    try:
        driver.activate_app(package)
    except Exception as exc:
        raise AndroidAutomationError(f"activate {label} via Appium failed: {exc}") from exc
    delay_s = float(app_cfg.get("activate_wait_s") or app_cfg.get("start_wait_s") or 1.0)
    if delay_s > 0:
        time.sleep(delay_s)


def _driver(auto_cfg: dict, *, app_cfg: Optional[dict] = None):
    webdriver, UiAutomator2Options, _AppiumBy = _import_appium()
    caps = dict(auto_cfg.get("capabilities") or {})
    caps.setdefault("platformName", "Android")
    caps.setdefault("automationName", "UiAutomator2")
    caps.setdefault("deviceName", auto_cfg.get("device_name") or "Android")
    caps.setdefault(
        "uiautomator2ServerReadTimeout",
        int(auto_cfg.get("uiautomator2_server_read_timeout_ms") or 15000),
    )
    if auto_cfg.get("adb_serial"):
        caps.setdefault("udid", auto_cfg.get("adb_serial"))
    if app_cfg:
        package = _app_package(app_cfg)
        activity = _app_activity(app_cfg)
        if package:
            caps.setdefault("appPackage", package)
        if activity:
            caps.setdefault("appActivity", activity)
    options = UiAutomator2Options()
    options.load_capabilities(caps)
    server_url = str(auto_cfg.get("appium_server_url") or "http://127.0.0.1:4723")
    try:
        driver = webdriver.Remote(
            command_executor=server_url,
            options=options,
        )
    except Exception as exc:
        detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        raise AndroidAutomationError(f"appium session failed at {server_url}: {detail}") from exc
    try:
        driver.implicitly_wait(float(auto_cfg.get("implicit_wait_s", 0.2)))
    except Exception:
        pass
    return driver


def _resource_id(package_name: str, value: str) -> str:
    if "/" in value or ":" in value:
        return value
    if not package_name:
        return value
    return f"{package_name}:id/{value}"


@dataclass
class StepRunner:
    driver: Any
    appium_by: Any
    default_package: str = ""
    log: Optional[Callable[[str], None]] = None

    def _log(self, message: str) -> None:
        if self.log:
            self.log(message)
        else:
            print(f"[android-gopay] {message}", flush=True)

    def _text_values(self, step: dict, key: str = "text") -> list[str]:
        values = step.get(f"{key}_any") or step.get(f"{key}s") or []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            values = []
        if step.get(key):
            values = [step.get(key)] + values
        return [str(value) for value in values if str(value).strip()]

    def _find_by_exact_text(self, values: list[str], step: dict):
        last_exc = None
        for value in values:
            escaped = value.replace('"', '\\"')
            selectors = [f'new UiSelector().text("{escaped}")']
            if step.get("match_content_desc", step.get("match_description", True)):
                selectors.append(f'new UiSelector().description("{escaped}")')
            for selector in selectors:
                try:
                    return self.driver.find_element(self.appium_by.ANDROID_UIAUTOMATOR, selector)
                except Exception as exc:
                    last_exc = exc
        if last_exc:
            raise last_exc
        raise AndroidAutomationError(f"empty text selector for step={step!r}")

    def _source_values(self) -> tuple[str, str]:
        source = self.driver.page_source or ""
        return source, html.unescape(source)

    def _source_contains_any_now(self, values: list[str]) -> bool:
        source_values = self._source_values()
        return any(v and any(v in item for item in source_values) for v in values)

    def _tap_element_row(self, element: Any, step: dict) -> None:
        try:
            rect = dict(getattr(element, "rect", {}) or {})
            x = float(rect.get("x") or 0) + float(rect.get("width") or 0) / 2
            y = float(rect.get("y") or 0) + float(rect.get("height") or 0) / 2
            if step.get("row_center_x", True):
                try:
                    size = self.driver.get_window_size()
                    x = float(size.get("width") or 0) * float(step.get("row_x_ratio") or 0.5)
                except Exception:
                    pass
            try:
                self.driver.execute_script("mobile: clickGesture", {"x": int(x), "y": int(y)})
                return
            except Exception:
                pass
            try:
                self.driver.tap([(int(x), int(y))])
                return
            except Exception:
                pass
        except Exception:
            pass
        element.click()

    def _find(self, step: dict):
        timeout = float(step.get("timeout_s", 20))
        deadline = time.time() + timeout
        last_exc = None
        page_source_gate = bool(step.get("page_source_gate", True))
        while True:
            try:
                if step.get("id"):
                    return self.driver.find_element(self.appium_by.ID, _resource_id(self.default_package, str(step["id"])))
                if step.get("xpath"):
                    return self.driver.find_element(self.appium_by.XPATH, str(step["xpath"]))
                if step.get("accessibility_id"):
                    return self.driver.find_element(self.appium_by.ACCESSIBILITY_ID, str(step["accessibility_id"]))
                exact_texts = self._text_values(step, "text")
                if exact_texts:
                    if page_source_gate and not self._source_contains_any_now(exact_texts):
                        raise AndroidAutomationError(f"text not present in current page_source: {exact_texts}")
                    return self._find_by_exact_text(exact_texts, step)
                if step.get("text_contains"):
                    escaped = str(step["text_contains"]).replace('"', '\\"')
                    if page_source_gate and not self._source_contains_any_now([str(step["text_contains"])]):
                        raise AndroidAutomationError(f"text not present in current page_source: {step['text_contains']!r}")
                    selectors = [f'new UiSelector().textContains("{escaped}")']
                    if step.get("match_content_desc", step.get("match_description", True)):
                        selectors.append(f'new UiSelector().descriptionContains("{escaped}")')
                    for selector in selectors:
                        try:
                            return self.driver.find_element(self.appium_by.ANDROID_UIAUTOMATOR, selector)
                        except Exception as exc:
                            last_exc = exc
                    raise last_exc
                if step.get("description_contains"):
                    escaped = str(step["description_contains"]).replace('"', '\\"')
                    if page_source_gate and not self._source_contains_any_now([str(step["description_contains"])]):
                        raise AndroidAutomationError(
                            f"description not present in current page_source: {step['description_contains']!r}"
                        )
                    return self.driver.find_element(
                        self.appium_by.ANDROID_UIAUTOMATOR,
                        f'new UiSelector().descriptionContains("{escaped}")',
                    )
            except Exception as exc:
                last_exc = exc
                if time.time() >= deadline:
                    break
                time.sleep(0.4)
        raise AndroidAutomationError(f"element not found for step={step!r}; last={last_exc}")

    def _source_has_any(self, values: list[str], timeout_s: float) -> bool:
        deadline = time.time() + timeout_s
        while True:
            if self._source_contains_any_now(values):
                return True
            if time.time() >= deadline:
                return False
            time.sleep(0.4)

    def _state_matches(self, state: dict, source: str) -> bool:
        if state.get("default"):
            return False
        any_values = [str(x) for x in (state.get("match_any") or state.get("values") or []) if str(x)]
        all_values = [str(x) for x in (state.get("match_all") or []) if str(x)]
        none_values = [str(x) for x in (state.get("match_none") or []) if str(x)]
        contains = str(state.get("text_contains") or "").strip()
        exact = str(state.get("text") or "").strip()
        if exact:
            any_values.append(f'text="{exact}"')
        if contains:
            any_values.append(contains)
        source_values = (source, html.unescape(source))
        if none_values and any(v and any(v in item for item in source_values) for v in none_values):
            return False
        if all_values and not all(v and any(v in item for item in source_values) for v in all_values):
            return False
        if any_values and not any(v and any(v in item for item in source_values) for v in any_values):
            return False
        return bool(any_values or all_values)

    def _detect_state(self, states: list[dict]) -> dict | None:
        source = self.driver.page_source or ""
        default_state = None
        for state in states:
            if not isinstance(state, dict):
                continue
            if state.get("default"):
                default_state = state
                continue
            if self._state_matches(state, source):
                return state
        return default_state

    def _dump(self, out_dir: Path, name: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{name}.xml").write_text(self.driver.page_source, encoding="utf-8")
        try:
            self.driver.save_screenshot(str(out_dir / f"{name}.png"))
        except Exception:
            pass

    def run(self, steps: list[dict], *, out_dir: Path) -> None:
        for idx, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                raise AndroidAutomationError(f"step #{idx} must be an object")
            action = str(step.get("action") or "").strip().lower()
            name = str(step.get("name") or f"step_{idx:02d}")
            self._log(f"step={name} action={action}")
            try:
                if action == "sleep":
                    time.sleep(float(step.get("seconds", 1)))
                elif action == "tap":
                    self._find(step).click()
                elif action == "tap_row":
                    self._tap_element_row(self._find(step), step)
                elif action == "tap_optional":
                    try:
                        self._find(step).click()
                    except AndroidAutomationError:
                        pass
                elif action == "tap_row_optional":
                    try:
                        self._tap_element_row(self._find(step), step)
                    except AndroidAutomationError:
                        pass
                elif action == "input":
                    el = self._find(step)
                    if step.get("clear", True):
                        el.clear()
                    el.send_keys(str(step.get("value") or ""))
                elif action == "wait":
                    self._find(step)
                elif action == "wait_text_any":
                    values = [str(x) for x in step.get("values", [])]
                    if not self._source_has_any(values, float(step.get("timeout_s", 20))):
                        raise AndroidAutomationError(f"none of expected values found: {values}")
                elif action == "back":
                    self.driver.back()
                elif action == "back_if_text_any":
                    values = [str(x) for x in step.get("values", [])]
                    if self._source_has_any(values, float(step.get("timeout_s", 1))):
                        self.driver.back()
                elif action == "press_keycode":
                    self.driver.press_keycode(int(step.get("keycode")))
                elif action == "dump":
                    self._dump(out_dir, name)
                elif action == "assert_text_any":
                    values = [str(x) for x in step.get("values", [])]
                    if not self._source_has_any(values, float(step.get("timeout_s", 20))):
                        raise AndroidAutomationError(f"none of expected values found: {values}")
                else:
                    raise AndroidAutomationError(f"unsupported action in step #{idx}: {action}")
            except Exception:
                safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or f"step_{idx:02d}"
                try:
                    self._dump(out_dir, f"{safe_name}_error")
                except Exception:
                    pass
                raise
            self._log(f"step={name} done")

    def run_states(
        self,
        states: list[dict],
        *,
        out_dir: Path,
        max_iterations: int = 30,
        settle_s: float = 0.6,
    ) -> dict:
        if not isinstance(states, list) or not states:
            raise AndroidAutomationError("state flow requires a non-empty states list")
        history: list[str] = []
        visits: dict[str, int] = {}
        for iteration in range(1, max(1, int(max_iterations)) + 1):
            state = self._detect_state(states)
            if not state:
                self._dump(out_dir, f"unknown_{iteration:02d}")
                raise AndroidAutomationError("unable to classify current GoPay page")
            name = str(state.get("name") or f"state_{iteration:02d}")
            history.append(name)
            visits[name] = visits.get(name, 0) + 1
            self._log(f"state={name} iteration={iteration} visits={visits[name]}")
            if state.get("dump_on_enter"):
                safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "state"
                self._dump(out_dir, f"state_{iteration:02d}_{safe_name}")
            if state.get("terminal"):
                steps = state.get("terminal_steps") or state.get("exit_steps") or state.get("steps") or state.get("actions") or []
                if isinstance(steps, list) and steps:
                    self._log(f"terminal_state={name} cleanup_steps={len(steps)}")
                    self.run(steps, out_dir=out_dir)
                    delay_s = float(state.get("settle_s") or settle_s)
                    if delay_s > 0:
                        time.sleep(delay_s)
                return {"terminal_state": name, "iterations": iteration, "history": history}
            max_visits = int(state.get("max_visits") or 5)
            if max_visits > 0 and visits[name] > max_visits:
                raise AndroidAutomationError(f"state {name!r} repeated {visits[name]} times; history={history}")
            steps = state.get("steps") or state.get("actions") or []
            if not isinstance(steps, list) or not steps:
                raise AndroidAutomationError(f"state {name!r} has no steps/actions")
            self.run(steps, out_dir=out_dir)
            delay_s = float(state.get("settle_s") or settle_s)
            if delay_s > 0:
                time.sleep(delay_s)
        raise AndroidAutomationError(f"state flow exceeded {max_iterations} iterations; history={history}")


def cmd_inspect(args: argparse.Namespace) -> int:
    cfg = _load_json(Path(args.config))
    auto_cfg = _automation_cfg(cfg)
    _adb_connect(auto_cfg)
    _configure_screen_awake(auto_cfg)
    _set_android_proxy(auto_cfg)
    driver = _driver(auto_cfg)
    try:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "page.xml").write_text(driver.page_source, encoding="utf-8")
        driver.save_screenshot(str(out_dir / "screen.png"))
        print(json.dumps({"ok": True, "out_dir": str(out_dir)}, ensure_ascii=False))
        return 0
    finally:
        driver.quit()
        _clear_android_proxy(auto_cfg)


def cmd_otp(args: argparse.Namespace) -> int:
    cfg = _load_json(Path(args.config))
    auto_cfg = _automation_cfg(cfg)
    otp_cfg = _section(auto_cfg, "otp")
    timeout_s = float(args.timeout or otp_cfg.get("timeout_s", 300))
    interval_s = float(otp_cfg.get("poll_interval_s", 2))
    notification_source = str(otp_cfg.get("notification_source") or otp_cfg.get("read_mode") or "auto").strip().lower()
    _adb_connect(auto_cfg)
    _configure_screen_awake(auto_cfg)
    driver = None
    if notification_source in ("", "auto", "appium"):
        try:
            driver = _driver(auto_cfg)
        except Exception as exc:
            if notification_source == "appium":
                raise
            detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            print(f"[android-gopay] appium session failed, fallback to adb: {detail}", file=sys.stderr)
    deadline = time.time() + timeout_s
    try:
        while time.time() < deadline:
            payload = None
            try:
                if driver is not None and notification_source in ("", "auto", "appium"):
                    payload = driver.execute_script("mobile: getNotifications", {})
            except Exception as exc:
                detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
                print(f"[android-gopay] appium notification poll failed: {detail}", file=sys.stderr)
                if notification_source == "appium":
                    payload = None
                else:
                    payload = _adb_notification_payload(auto_cfg, otp_cfg)
            if payload is None and notification_source in ("auto", "adb", "dumpsys", "adb_dumpsys"):
                payload = _adb_notification_payload(auto_cfg, otp_cfg)
            if payload is not None:
                code = _find_otp_in_notifications(payload, otp_cfg)
                if code:
                    print(code)
                    return 0
            time.sleep(max(0.5, interval_s))
        return 1
    finally:
        if driver is not None:
            driver.quit()


def cmd_unlink(args: argparse.Namespace) -> int:
    cfg = _load_json(Path(args.config))
    auto_cfg = _automation_cfg(cfg)
    unlink_cfg = _section(auto_cfg, "gopay_unlink")
    steps = unlink_cfg.get("steps") or []
    states = unlink_cfg.get("states") or unlink_cfg.get("pages") or []
    if (not isinstance(states, list) or not states) and (not isinstance(steps, list) or not steps):
        raise AndroidAutomationError("android_automation.gopay_unlink.states or steps is empty; run inspect first")
    _adb_connect(auto_cfg)
    _configure_screen_awake(auto_cfg)
    _set_android_proxy(auto_cfg)
    _keep_screen_awake(auto_cfg)
    _activate_app_adb(auto_cfg, unlink_cfg, label="gopay")
    _, _UiAutomator2Options, AppiumBy = _import_appium()
    driver = _driver(auto_cfg, app_cfg=unlink_cfg)
    completed = False
    try:
        if _app_package(unlink_cfg):
            try:
                _activate_app_driver(driver, unlink_cfg, label="gopay")
            except Exception:
                pass
        runner = StepRunner(driver, AppiumBy, default_package=_app_package(unlink_cfg))
        if isinstance(states, list) and states:
            result = runner.run_states(
                states,
                out_dir=Path(args.out),
                max_iterations=int(unlink_cfg.get("state_max_iterations") or 30),
                settle_s=float(unlink_cfg.get("state_settle_s") or 0.6),
            )
            print(json.dumps({"ok": True, "states": result}, ensure_ascii=False))
        else:
            runner.run(steps, out_dir=Path(args.out))
            print(json.dumps({"ok": True, "steps": len(steps)}, ensure_ascii=False))
        completed = True
        return 0
    finally:
        try:
            Path(args.out).mkdir(parents=True, exist_ok=True)
            (Path(args.out) / "final.xml").write_text(driver.page_source, encoding="utf-8")
            driver.save_screenshot(str(Path(args.out) / "final.png"))
        except Exception:
            pass
        driver.quit()
        if completed and unlink_cfg.get("exit_to_home_on_complete", True):
            _adb_best_effort(auto_cfg, ["shell", "input", "keyevent", "3"], timeout=5.0)
        _clear_android_proxy(auto_cfg)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Android Appium helper for GoPay automation")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="JSON config path")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_inspect = sub.add_parser("inspect", help="dump current Android UI tree and screenshot")
    p_inspect.add_argument("--out", default="output/android-inspect")
    p_inspect.set_defaults(func=cmd_inspect)

    p_otp = sub.add_parser("otp", help="print latest WhatsApp/GoPay OTP from Android notifications")
    p_otp.add_argument("--timeout", type=float, default=0)
    p_otp.set_defaults(func=cmd_otp)

    p_unlink = sub.add_parser("unlink", help="run configured GoPay unlink UI steps")
    p_unlink.add_argument("--out", default="output/android-gopay-unlink")
    p_unlink.set_defaults(func=cmd_unlink)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AndroidAutomationError as exc:
        print(f"[android-gopay] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
