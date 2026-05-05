#!/usr/bin/env python3
"""Android/Appium helper for GoPay OTP capture and configurable UI flows.

The script is intentionally data-driven. It can read Android notifications for
WhatsApp OTPs, dump the current UI tree for selector discovery, and execute a
configured GoPay unlink flow after the selectors have been recorded from the
user-owned emulator/device.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


DEFAULT_CONFIG = Path(__file__).with_name("config.android-gopay.example.json")
DEFAULT_CODE_REGEX = r"(?<!\d)(\d{6})(?!\d)"
DEFAULT_KEYWORDS = ("gopay", "gojek", "whatsapp", "otp", "kode", "verifikasi", "verification", "code")


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


def _extract_otp_from_text(text: str, code_regex: str = DEFAULT_CODE_REGEX) -> str:
    if not text:
        return ""
    patterns = [
        r"(?:otp|one[-\s]*time|verification|verify|code|kode|verifikasi|gopay|gojek|whatsapp)[^\d]{0,100}(\d{4,8})(?!\d)",
        r"(?<!\d)(\d{4,8})(?!\d)[^\n\r]{0,100}(?:otp|one[-\s]*time|verification|verify|code|kode|verifikasi|gopay|gojek)",
        code_regex or DEFAULT_CODE_REGEX,
    ]
    for pattern in patterns:
        try:
            matches = list(re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL))
        except re.error:
            continue
        for match in reversed(matches):
            groups = match.groups() or (match.group(0),)
            for group in reversed(groups):
                digits = re.sub(r"\D", "", str(group or ""))
                if 4 <= len(digits) <= 8:
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
    for item in reversed(list(_iter_notifications(payload))):
        text = _notification_text(item)
        package_name = _notification_package(item)
        if not _matches_filters(text, package_name, otp_cfg):
            continue
        code = _extract_otp_from_text(text, code_regex=code_regex)
        if code:
            return code
    return ""


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
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _adb_connect(auto_cfg: dict) -> None:
    serial = str(auto_cfg.get("adb_serial") or "").strip()
    if not serial or ":" not in serial:
        return
    adb_path = str(auto_cfg.get("adb_path") or "adb")
    proc = subprocess.run([adb_path, "connect", serial], capture_output=True, text=True, timeout=20, check=False)
    if proc.returncode != 0:
        raise AndroidAutomationError(f"adb connect failed: {proc.stderr or proc.stdout}")


def _set_android_proxy(auto_cfg: dict) -> None:
    proxy_cfg = auto_cfg.get("proxy") or {}
    if not isinstance(proxy_cfg, dict) or not proxy_cfg.get("enabled"):
        return
    value = str(proxy_cfg.get("http_proxy") or proxy_cfg.get("host_port") or "").strip()
    if not value:
        proxy_url = str(proxy_cfg.get("url") or "").strip()
        m = re.match(r"^[a-zA-Z0-9+.-]+://(?:[^@/]+@)?([^/:]+):(\d+)", proxy_url)
        if m:
            value = f"{m.group(1)}:{m.group(2)}"
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


def _driver(auto_cfg: dict, *, app_cfg: Optional[dict] = None):
    webdriver, UiAutomator2Options, _AppiumBy = _import_appium()
    caps = dict(auto_cfg.get("capabilities") or {})
    caps.setdefault("platformName", "Android")
    caps.setdefault("automationName", "UiAutomator2")
    caps.setdefault("deviceName", auto_cfg.get("device_name") or "Android")
    if auto_cfg.get("adb_serial"):
        caps.setdefault("udid", auto_cfg.get("adb_serial"))
    if app_cfg:
        if app_cfg.get("package"):
            caps.setdefault("appPackage", app_cfg["package"])
        if app_cfg.get("activity"):
            caps.setdefault("appActivity", app_cfg["activity"])
    options = UiAutomator2Options()
    options.load_capabilities(caps)
    return webdriver.Remote(
        command_executor=str(auto_cfg.get("appium_server_url") or "http://127.0.0.1:4723"),
        options=options,
    )


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

    def _find(self, step: dict):
        timeout = float(step.get("timeout_s", 20))
        deadline = time.time() + timeout
        last_exc = None
        while time.time() < deadline:
            try:
                if step.get("id"):
                    return self.driver.find_element(self.appium_by.ID, _resource_id(self.default_package, str(step["id"])))
                if step.get("xpath"):
                    return self.driver.find_element(self.appium_by.XPATH, str(step["xpath"]))
                if step.get("accessibility_id"):
                    return self.driver.find_element(self.appium_by.ACCESSIBILITY_ID, str(step["accessibility_id"]))
                if step.get("text"):
                    escaped = str(step["text"]).replace('"', '\\"')
                    return self.driver.find_element(
                        self.appium_by.ANDROID_UIAUTOMATOR,
                        f'new UiSelector().text("{escaped}")',
                    )
                if step.get("text_contains"):
                    escaped = str(step["text_contains"]).replace('"', '\\"')
                    return self.driver.find_element(
                        self.appium_by.ANDROID_UIAUTOMATOR,
                        f'new UiSelector().textContains("{escaped}")',
                    )
                if step.get("description_contains"):
                    escaped = str(step["description_contains"]).replace('"', '\\"')
                    return self.driver.find_element(
                        self.appium_by.ANDROID_UIAUTOMATOR,
                        f'new UiSelector().descriptionContains("{escaped}")',
                    )
            except Exception as exc:
                last_exc = exc
                time.sleep(0.4)
        raise AndroidAutomationError(f"element not found for step={step!r}; last={last_exc}")

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
            if action == "sleep":
                time.sleep(float(step.get("seconds", 1)))
            elif action == "tap":
                self._find(step).click()
            elif action == "input":
                el = self._find(step)
                if step.get("clear", True):
                    el.clear()
                el.send_keys(str(step.get("value") or ""))
            elif action == "wait":
                self._find(step)
            elif action == "back":
                self.driver.back()
            elif action == "press_keycode":
                self.driver.press_keycode(int(step.get("keycode")))
            elif action == "dump":
                self._dump(out_dir, name)
            elif action == "assert_text_any":
                values = [str(x) for x in step.get("values", [])]
                source = self.driver.page_source
                if not any(v in source for v in values):
                    raise AndroidAutomationError(f"none of expected values found: {values}")
            else:
                raise AndroidAutomationError(f"unsupported action in step #{idx}: {action}")


def cmd_inspect(args: argparse.Namespace) -> int:
    cfg = _load_json(Path(args.config))
    auto_cfg = _automation_cfg(cfg)
    _adb_connect(auto_cfg)
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
    _adb_connect(auto_cfg)
    driver = _driver(auto_cfg)
    deadline = time.time() + timeout_s
    try:
        while time.time() < deadline:
            try:
                payload = driver.execute_script("mobile: getNotifications", {})
                code = _find_otp_in_notifications(payload, otp_cfg)
                if code:
                    print(code)
                    return 0
            except Exception as exc:
                detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
                print(f"[android-gopay] notification poll failed: {detail}", file=sys.stderr)
            time.sleep(max(0.5, interval_s))
        return 1
    finally:
        driver.quit()


def cmd_unlink(args: argparse.Namespace) -> int:
    cfg = _load_json(Path(args.config))
    auto_cfg = _automation_cfg(cfg)
    unlink_cfg = _section(auto_cfg, "gopay_unlink")
    steps = unlink_cfg.get("steps") or []
    if not isinstance(steps, list) or not steps:
        raise AndroidAutomationError("android_automation.gopay_unlink.steps is empty; run inspect first")
    _adb_connect(auto_cfg)
    _set_android_proxy(auto_cfg)
    _, _UiAutomator2Options, AppiumBy = _import_appium()
    driver = _driver(auto_cfg)
    try:
        if unlink_cfg.get("package"):
            try:
                driver.activate_app(str(unlink_cfg["package"]))
            except Exception:
                pass
        runner = StepRunner(driver, AppiumBy, default_package=str(unlink_cfg.get("package") or ""))
        runner.run(steps, out_dir=Path(args.out))
        print(json.dumps({"ok": True, "steps": len(steps)}, ensure_ascii=False))
        return 0
    finally:
        try:
            Path(args.out).mkdir(parents=True, exist_ok=True)
            (Path(args.out) / "final.xml").write_text(driver.page_source, encoding="utf-8")
            driver.save_screenshot(str(Path(args.out) / "final.png"))
        except Exception:
            pass
        driver.quit()
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
