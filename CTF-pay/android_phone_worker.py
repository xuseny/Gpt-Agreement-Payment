#!/usr/bin/env python3
"""Local Android phone worker for WebUI GoPay OTP automation.

This process runs on the machine that has the Android phone connected by ADB.
It polls Android notifications through Appium, extracts GoPay/WhatsApp OTPs,
and pushes the latest code into the remote WebUI SQLite OTP state endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import android_gopay_automation as android  # noqa: E402


DEFAULT_CONFIG = HERE / "config.android-gopay.example.json"
DEFAULT_PUSH_PATH = "/api/whatsapp/sidecar/state"
DEFAULT_STATE_FILE = Path("output/android-phone-worker-state.json")


class PhoneWorkerError(RuntimeError):
    pass


def _worker_cfg(cfg: dict) -> dict:
    value = cfg.get("phone_worker") or cfg.get("android_phone_worker") or {}
    if not isinstance(value, dict):
        raise PhoneWorkerError("phone_worker must be an object")
    return value


def _clean_url(value: str) -> str:
    return str(value or "").strip().rstrip("/")


def _join_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{_clean_url(base)}/{path.lstrip('/')}"


def _push_url(worker_cfg: dict) -> str:
    explicit = str(worker_cfg.get("push_url") or "").strip()
    if explicit:
        return explicit
    base = (
        os.environ.get("PHONE_WORKER_SERVER_BASE_URL")
        or worker_cfg.get("server_base_url")
        or worker_cfg.get("webui_base_url")
        or ""
    )
    if not str(base).strip():
        raise PhoneWorkerError("phone_worker.server_base_url or PHONE_WORKER_SERVER_BASE_URL is required")
    path = str(worker_cfg.get("push_path") or DEFAULT_PUSH_PATH)
    return _join_url(str(base), path)


def _relay_token(worker_cfg: dict) -> str:
    token = os.environ.get("PHONE_WORKER_RELAY_TOKEN") or worker_cfg.get("relay_token") or ""
    token = str(token).strip()
    if not token:
        raise PhoneWorkerError("phone_worker.relay_token or PHONE_WORKER_RELAY_TOKEN is required")
    return token


def _state_file(worker_cfg: dict) -> Path:
    raw = worker_cfg.get("state_file") or DEFAULT_STATE_FILE
    return Path(str(raw)).expanduser()


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _coerce_epoch(value: Any) -> Optional[float]:
    return android._coerce_epoch(value)


def _notification_epoch(item: Any) -> Optional[float]:
    return android._notification_epoch(item)


def _fingerprint(code: str, package_name: str, text: str, notification_ts: Optional[float]) -> str:
    ts_part = str(int(notification_ts)) if notification_ts else ""
    raw = "\n".join([code, package_name, text, ts_part])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _extract_otp_event(payload: Any, otp_cfg: dict, *, now: Optional[float] = None, engine: str = "android_appium") -> dict | None:
    now = time.time() if now is None else now
    code_regex = str(otp_cfg.get("code_regex") or android.DEFAULT_CODE_REGEX)
    candidates = []
    for index, item in enumerate(list(android._iter_notifications(payload))):
        text = android._notification_text(item)
        package_name = android._notification_package(item)
        if not android._matches_filters(text, package_name, otp_cfg):
            continue
        code = android._extract_otp_from_text(text, code_regex=code_regex)
        if not code:
            continue
        notification_ts = _notification_epoch(item)
        event_ts = notification_ts or now
        candidates.append({
            "otp": code,
            "ts": event_ts,
            "notification_ts": notification_ts,
            "from": package_name or "android_notification",
            "source": "android_phone_worker",
            "engine": engine,
            "text": text[:500],
            "fingerprint": _fingerprint(code, package_name, text, notification_ts),
            "_rank_has_ts": notification_ts is not None,
            "_rank_ts": notification_ts or 0.0,
            "_rank_index": index,
        })
    if not candidates:
        return None
    event = max(
        candidates,
        key=lambda item: (bool(item["_rank_has_ts"]), float(item["_rank_ts"]), int(item["_rank_index"])),
    )
    event.pop("_rank_has_ts", None)
    event.pop("_rank_ts", None)
    event.pop("_rank_index", None)
    return event


def _post_json(url: str, token: str, payload: dict, *, timeout: float) -> dict:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-WA-Relay-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if not body:
                return {"ok": 200 <= resp.status < 300}
            try:
                return json.loads(body)
            except ValueError:
                return {"ok": 200 <= resp.status < 300, "body": body}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise PhoneWorkerError(f"push failed: HTTP {exc.code} {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        raise PhoneWorkerError(f"push failed: {exc}") from exc


def _build_push_payload(event: dict, auto_cfg: dict) -> dict:
    item = {
        "otp": event["otp"],
        "ts": event["ts"],
        "from": event.get("from") or "android_notification",
        "source": event.get("source") or "android_phone_worker",
        "engine": event.get("engine") or "android_appium",
        "text": event.get("text") or "",
        "notification_ts": event.get("notification_ts"),
    }
    return {
        "status": "connected",
        "latest": item,
        "android_phone_worker": {
            "status": "connected",
            "updated_at": time.time(),
            "adb_serial": str(auto_cfg.get("adb_serial") or ""),
            "device_name": str(auto_cfg.get("device_name") or "Android"),
        },
    }


def _should_skip_event(event: dict, state: dict, *, first_scan: bool, ignore_existing: bool, dedupe_window_s: float) -> str:
    fp = str(event.get("fingerprint") or "")
    now = float(event.get("ts") or time.time())
    if fp and fp == state.get("last_fingerprint"):
        return "duplicate_fingerprint"
    try:
        last_pushed_event_ts = float(state.get("last_pushed_event_ts") or 0.0)
    except Exception:
        last_pushed_event_ts = 0.0
    if last_pushed_event_ts and now <= last_pushed_event_ts:
        return "stale_notification"
    last_code = str(state.get("last_code") or "")
    try:
        last_at = float(state.get("last_pushed_at") or 0.0)
    except Exception:
        last_at = 0.0
    if last_code and last_code == str(event.get("otp") or "") and now - last_at < dedupe_window_s:
        return "duplicate_code"
    if first_scan and ignore_existing:
        return "initial_existing_notification"
    return ""


def _push_delay_remaining(event: dict, delay_s: float, *, now: Optional[float] = None) -> float:
    if delay_s <= 0:
        return 0.0
    current = time.time() if now is None else now
    event_ts = _coerce_epoch(event.get("notification_ts")) or _coerce_epoch(event.get("ts")) or current
    age_s = max(0.0, current - event_ts)
    return max(0.0, delay_s - age_s)


def _remember_event(path: Path, state: dict, event: dict, *, pushed: bool) -> None:
    state.update({
        "last_fingerprint": event.get("fingerprint") or "",
        "last_code": event.get("otp") or "",
        "last_seen_at": time.time(),
    })
    if pushed:
        state["last_pushed_at"] = time.time()
        state["last_pushed_event_ts"] = float(event.get("ts") or 0.0)
    _save_state(path, state)


def _log(message: str) -> None:
    print(f"[android-phone-worker] {message}", flush=True)


def run_worker(args: argparse.Namespace) -> int:
    cfg = android._load_json(Path(args.config))
    auto_cfg = android._automation_cfg(cfg)
    worker_cfg = _worker_cfg(cfg)
    otp_cfg = android._section(auto_cfg, "otp")

    interval_s = float(args.interval or worker_cfg.get("poll_interval_s") or otp_cfg.get("poll_interval_s") or 2)
    post_timeout_s = float(worker_cfg.get("post_timeout_s") or 10)
    dedupe_window_s = float(worker_cfg.get("dedupe_window_s") or 180)
    push_delay_s = float(
        worker_cfg.get("push_delay_after_notification_s")
        or worker_cfg.get("push_delay_s")
        or 20
    )
    skip_log_interval_s = float(worker_cfg.get("skip_log_interval_s") or 60)
    notification_source = str(
        worker_cfg.get("notification_source")
        or otp_cfg.get("notification_source")
        or "adb"
    ).strip().lower()
    appium_retry_s = float(worker_cfg.get("appium_retry_s") or 60)
    ignore_existing = bool(worker_cfg.get("ignore_existing_on_start", True)) and not args.push_existing
    state_path = _state_file(worker_cfg)
    state = _load_state(state_path)
    url = _push_url(worker_cfg)
    token = _relay_token(worker_cfg)

    android._adb_connect(auto_cfg)
    if worker_cfg.get("set_proxy_on_start", True):
        android._set_android_proxy(auto_cfg)

    driver = None
    appium_disabled_until = 0.0
    first_scan = True
    try:
        while True:
            payload = None
            engine = "android_adb_dumpsys"
            try:
                if notification_source in ("auto", "appium") and time.time() >= appium_disabled_until:
                    if driver is None:
                        driver = android._driver(auto_cfg)
                        _log("appium session ready")
                    payload = driver.execute_script("mobile: getNotifications", {})
                    engine = "android_appium"
            except Exception as exc:
                detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
                _log(f"appium notification poll failed: {detail}")
                try:
                    if driver is not None:
                        driver.quit()
                except Exception:
                    pass
                driver = None
                appium_disabled_until = time.time() + appium_retry_s
                if notification_source == "appium" and args.once:
                    return 2
                if notification_source == "appium":
                    time.sleep(max(1.0, interval_s))
                    continue

            if payload is None and notification_source in ("", "auto", "adb", "dumpsys", "adb_dumpsys"):
                try:
                    payload = android._adb_notification_payload(auto_cfg, otp_cfg)
                    engine = "android_adb_dumpsys"
                except Exception as exc:
                    detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
                    _log(f"adb notification poll failed: {detail}")
                    if args.once:
                        return 2
                    time.sleep(max(1.0, interval_s))
                    continue

            event = _extract_otp_event(payload, otp_cfg, engine=engine) if payload is not None else None

            if not event:
                if args.once:
                    _log("no otp notification found")
                    return 1
                first_scan = False
                time.sleep(max(0.5, interval_s))
                continue

            reason = _should_skip_event(
                event,
                state,
                first_scan=first_scan,
                ignore_existing=ignore_existing,
                dedupe_window_s=dedupe_window_s,
            )
            if args.force:
                reason = ""
            if reason:
                skip_key = f"{reason}:{event.get('fingerprint') or event.get('otp') or ''}"
                try:
                    last_skip_log_at = float(state.get("last_skip_log_at") or 0.0)
                except Exception:
                    last_skip_log_at = 0.0
                now = time.time()
                should_log_skip = (
                    skip_key != state.get("last_skip_log_key")
                    or now - last_skip_log_at >= skip_log_interval_s
                )
                _remember_event(state_path, state, event, pushed=False)
                if should_log_skip:
                    _log(f"skip otp {event['otp']} ({reason})")
                    state["last_skip_log_key"] = skip_key
                    state["last_skip_log_at"] = now
                    _save_state(state_path, state)
                if args.once:
                    return 1
                first_scan = False
                time.sleep(max(0.5, interval_s))
                continue

            delay_remaining_s = 0.0 if args.force else _push_delay_remaining(event, push_delay_s)
            if delay_remaining_s > 0:
                delay_key = f"{event.get('fingerprint') or event.get('otp') or ''}:{int(float(event.get('ts') or 0))}"
                try:
                    last_delay_log_at = float(state.get("last_delay_log_at") or 0.0)
                except Exception:
                    last_delay_log_at = 0.0
                now = time.time()
                should_log_delay = (
                    delay_key != state.get("last_delay_log_key")
                    or now - last_delay_log_at >= skip_log_interval_s
                )
                if should_log_delay:
                    _log(
                        f"wait otp {event['otp']} "
                        f"{delay_remaining_s:.1f}s before push"
                    )
                    state["last_delay_log_key"] = delay_key
                    state["last_delay_log_at"] = now
                    _save_state(state_path, state)
                first_scan = False
                time.sleep(max(0.5, min(interval_s, delay_remaining_s)))
                continue

            payload = _build_push_payload(event, auto_cfg)
            if args.dry_run:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                try:
                    _post_json(url, token, payload, timeout=post_timeout_s)
                    _log(f"pushed otp {event['otp']} to {url}")
                except PhoneWorkerError as exc:
                    _log(str(exc))
                    if args.once:
                        return 2
                    first_scan = False
                    time.sleep(max(1.0, interval_s))
                    continue
            if not args.dry_run:
                _remember_event(state_path, state, event, pushed=True)
            if args.once:
                return 0
            first_scan = False
            time.sleep(max(0.5, interval_s))
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        if worker_cfg.get("clear_proxy_on_exit", False):
            android._clear_android_proxy(auto_cfg)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Local Android phone worker for WebUI OTP push")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="JSON config path")
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    parser.add_argument("--dry-run", action="store_true", help="print push payload without posting")
    parser.add_argument("--force", action="store_true", help="bypass startup and duplicate suppression")
    parser.add_argument("--push-existing", action="store_true", help="allow pushing the first OTP seen on startup")
    parser.add_argument("--interval", type=float, default=0.0, help="override poll interval seconds")
    args = parser.parse_args(argv)
    try:
        return run_worker(args)
    except (PhoneWorkerError, android.AndroidAutomationError) as exc:
        print(f"[android-phone-worker] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
