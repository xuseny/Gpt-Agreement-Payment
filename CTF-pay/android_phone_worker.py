#!/usr/bin/env python3
"""Local Android phone worker for WebUI GoPay OTP automation.

This process runs on the machine that has the Android phone connected by ADB.
It polls Android notifications through Appium, extracts GoPay/WhatsApp OTPs,
and pushes the latest code into the remote WebUI SQLite OTP state endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import android_gopay_automation as android  # noqa: E402


DEFAULT_CONFIG = HERE / "config.android-gopay.example.json"
DEFAULT_PUSH_PATH = "/api/whatsapp/sidecar/state"
DEFAULT_RUN_LOGS_PATH = "/api/run/sidecar/logs"
DEFAULT_STATE_FILE = Path("output/android-phone-worker-state.json")
DEFAULT_GOPAY_UNLINK_TRIGGER_STRINGS = (
    "GoPay \u6388\u6743 + \u6263\u6b3e\u5b8c\u6210",
    "GoPay&&\u6388\u6743&&\u6263\u6b3e&&\u5b8c\u6210",
    "GoPay&&poll&&\u7ed3\u679c",
)
DEFAULT_OTP_FOCUS_RUN_LOG_TRIGGER_STRINGS = (
    "[gopay] waiting WhatsApp OTP",
    "[gopay] requesting WhatsApp OTP",
    "waiting WhatsApp OTP from relay",
    "waiting WhatsApp OTP from file",
    "waiting WhatsApp OTP from command",
    "GOPAY_OTP_REQUEST",
    "gopay&&whatsapp&&otp",
)
DEFAULT_OTP_FOCUS_NOTIFICATION_KEYWORDS = (
    "gopay",
    "gojek",
    "otp",
    "one-time",
    "one time",
    "password",
    "kode",
    "verifikasi",
    "verification",
    "code",
)
DEFAULT_OTP_FOCUS_RUN_LOG_CLEAR_MARKERS = (
    "[gopay] received WhatsApp OTP from relay:",
    "[gopay] submitting WhatsApp OTP",
    "[gopay] otp ok",
    "[gopay] linking complete",
    "[gopay] chatgpt verify ok",
    "payment succeeded",
)
MAX_PUSH_HISTORY = 200


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


def _gopay_unlink_worker_cfg(worker_cfg: dict) -> dict:
    value = worker_cfg.get("gopay_unlink") or worker_cfg.get("auto_gopay_unlink") or {}
    if value is True:
        return {"enabled": True}
    if not isinstance(value, dict):
        raise PhoneWorkerError("phone_worker.gopay_unlink must be an object")
    return value


def _otp_focus_worker_cfg(worker_cfg: dict) -> dict:
    value = worker_cfg.get("otp_focus") or worker_cfg.get("whatsapp_focus") or {}
    if value is True:
        return {"enabled": True, "package": "com.whatsapp"}
    if not isinstance(value, dict):
        raise PhoneWorkerError("phone_worker.otp_focus must be an object")
    return value


def _run_logs_url(worker_cfg: dict, *section_cfgs: dict) -> str:
    explicit = ""
    for section_cfg in section_cfgs:
        if isinstance(section_cfg, dict) and section_cfg.get("run_logs_url"):
            explicit = str(section_cfg.get("run_logs_url") or "").strip()
            break
    if not explicit:
        explicit = str(worker_cfg.get("run_logs_url") or "").strip()
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
    path = ""
    for section_cfg in section_cfgs:
        if isinstance(section_cfg, dict) and section_cfg.get("run_logs_path"):
            path = str(section_cfg.get("run_logs_path") or "")
            break
    if not path:
        path = str(worker_cfg.get("run_logs_path") or DEFAULT_RUN_LOGS_PATH)
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


def _extract_otp_events(payload: Any, otp_cfg: dict, *, now: Optional[float] = None, engine: str = "android_appium") -> list[dict]:
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
    candidates.sort(
        key=lambda item: (bool(item["_rank_has_ts"]), float(item["_rank_ts"]), int(item["_rank_index"])),
        reverse=True,
    )
    for event in candidates:
        event.pop("_rank_has_ts", None)
        event.pop("_rank_ts", None)
        event.pop("_rank_index", None)
    return candidates


def _extract_otp_event(payload: Any, otp_cfg: dict, *, now: Optional[float] = None, engine: str = "android_appium") -> dict | None:
    events = _extract_otp_events(payload, otp_cfg, now=now, engine=engine)
    return events[0] if events else None


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
    except (http.client.HTTPException, OSError, TimeoutError) as exc:
        raise PhoneWorkerError(f"push failed: {exc}") from exc


def _get_json(url: str, token: str, *, timeout: float) -> dict:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"X-WA-Relay-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if not body:
                return {"ok": 200 <= resp.status < 300}
            try:
                data = json.loads(body)
            except ValueError:
                return {"ok": 200 <= resp.status < 300, "body": body}
            return data if isinstance(data, dict) else {"ok": 200 <= resp.status < 300, "data": data}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise PhoneWorkerError(f"run log poll failed: HTTP {exc.code} {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        raise PhoneWorkerError(f"run log poll failed: {exc}") from exc
    except (http.client.HTTPException, OSError, TimeoutError) as exc:
        raise PhoneWorkerError(f"run log poll failed: {exc}") from exc


def _fetch_run_log_payload(url: str, token: str, *, since_seq: int, limit: int, timeout: float) -> dict:
    query = urllib.parse.urlencode({
        "since": max(0, int(since_seq)),
        "limit": max(1, int(limit)),
    })
    sep = "&" if "?" in url else "?"
    return _get_json(f"{url}{sep}{query}", token, timeout=timeout)


def _entry_seq(entry: Any) -> int:
    if not isinstance(entry, dict):
        return 0
    try:
        return int(entry.get("seq") or 0)
    except Exception:
        return 0


def _entry_line(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("line") or "")
    return str(entry or "")


def _entry_ts(entry: Any) -> float:
    if not isinstance(entry, dict):
        return 0.0
    try:
        return float(entry.get("ts") or entry.get("time") or 0.0)
    except Exception:
        return 0.0


def _normalize_log_text(value: str) -> str:
    return " ".join(str(value or "").lower().split())


def _trigger_matches_line(line: str, trigger: str) -> bool:
    trigger = str(trigger or "").strip()
    if not trigger:
        return False
    normalized_line = _normalize_log_text(line)
    if "&&" in trigger:
        terms = [_normalize_log_text(part) for part in trigger.split("&&") if part.strip()]
        return bool(terms) and all(term in normalized_line for term in terms)
    return _normalize_log_text(trigger) in normalized_line


def _log_entry_matches_trigger(entry: Any, trigger_strings: list[str]) -> bool:
    line = _entry_line(entry)
    return any(_trigger_matches_line(line, trigger) for trigger in trigger_strings)


def _log_entry_matches_unlink_trigger(entry: Any, trigger_strings: list[str]) -> bool:
    return _log_entry_matches_trigger(entry, trigger_strings)


def _otp_focus_line_clears_wait(line: str) -> bool:
    normalized_line = _normalize_log_text(line)
    return any(
        _normalize_log_text(marker) in normalized_line
        for marker in DEFAULT_OTP_FOCUS_RUN_LOG_CLEAR_MARKERS
    )


def _log_entry_matches_otp_focus_trigger(entry: Any, trigger_strings: list[str]) -> bool:
    line = _entry_line(entry)
    if _otp_focus_line_clears_wait(line):
        return False
    return _log_entry_matches_trigger(entry, trigger_strings)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    try:
        return [str(item) for item in value if str(item).strip()]
    except TypeError:
        text = str(value).strip()
        return [text] if text else []


def _merged_trigger_strings(configured: Any, defaults: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in list(defaults) + _string_list(configured):
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _otp_focus_run_log_trigger_strings(focus_cfg: dict) -> list[str]:
    raw = (
        focus_cfg.get("run_log_trigger_strings")
        or focus_cfg.get("log_trigger_strings")
        or focus_cfg.get("run_log_triggers")
    )
    return _merged_trigger_strings(raw, DEFAULT_OTP_FOCUS_RUN_LOG_TRIGGER_STRINGS)


def _gopay_unlink_trigger_strings(unlink_worker_cfg: dict) -> list[str]:
    raw = unlink_worker_cfg.get("trigger_strings") or unlink_worker_cfg.get("triggers")
    return _merged_trigger_strings(raw, DEFAULT_GOPAY_UNLINK_TRIGGER_STRINGS)


def _latest_matching_entry(lines: list[Any], matcher: Callable[[Any, list[str]], bool], trigger_strings: list[str]) -> Any | None:
    matches = [entry for entry in lines if matcher(entry, trigger_strings)]
    if not matches:
        return None
    return max(matches, key=_entry_seq)


def _run_log_focus_event(entry: Any, *, now: Optional[float] = None) -> dict:
    now = _entry_ts(entry) or (time.time() if now is None else now)
    seq = _entry_seq(entry)
    line = _entry_line(entry)
    fingerprint_raw = f"otp-focus-run-log\n{seq}\n{line}"
    return {
        "otp": "",
        "ts": now,
        "notification_ts": None,
        "from": "run_log",
        "source": "android_phone_worker",
        "engine": "run_log",
        "text": line[:500],
        "label": "otp wait log",
        "fingerprint": hashlib.sha256(fingerprint_raw.encode("utf-8", errors="ignore")).hexdigest(),
    }


def _run_configured_unlink(config_path: str, out_dir: str, *, timeout_s: float = 0.0) -> int:
    cmd = [
        sys.executable,
        str(HERE / "android_gopay_automation.py"),
        "--config",
        config_path,
        "unlink",
        "--out",
        out_dir,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s if timeout_s > 0 else None,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        for stream_name, stream in (("stdout", exc.stdout), ("stderr", exc.stderr)):
            if stream:
                for line in str(stream).splitlines()[-20:]:
                    _log(f"gopay unlink {stream_name}: {line[:300]}")
        raise PhoneWorkerError(f"gopay unlink flow timeout after {timeout_s:.1f}s") from exc
    for stream_name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        if stream:
            for line in str(stream).splitlines()[-20:]:
                _log(f"gopay unlink {stream_name}: {line[:300]}")
    return int(proc.returncode)


def _notification_focus_keywords(focus_cfg: dict) -> list[str]:
    raw = focus_cfg.get("notification_keywords") or focus_cfg.get("keywords")
    if raw is None:
        raw = DEFAULT_OTP_FOCUS_NOTIFICATION_KEYWORDS
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(item).lower() for item in raw if str(item).strip()]


def _extract_otp_focus_hint(
    payload: Any,
    otp_cfg: dict,
    focus_cfg: dict,
    *,
    now: Optional[float] = None,
    engine: str = "android_appium",
) -> dict | None:
    if not focus_cfg.get("enabled", False):
        return None
    if not focus_cfg.get("focus_on_notification", True):
        return None
    now = time.time() if now is None else now
    code_regex = str(otp_cfg.get("code_regex") or android.DEFAULT_CODE_REGEX)
    keywords = _notification_focus_keywords(focus_cfg)
    candidates = []
    for index, item in enumerate(list(android._iter_notifications(payload))):
        text = android._notification_text(item)
        package_name = android._notification_package(item)
        if not android._matches_filters(text, package_name, otp_cfg):
            continue
        if android._extract_otp_from_text(text, code_regex=code_regex):
            continue
        text_l = text.lower()
        if keywords and not any(keyword in text_l for keyword in keywords):
            continue
        notification_ts = _notification_epoch(item)
        event_ts = notification_ts or now
        candidates.append({
            "otp": "",
            "ts": event_ts,
            "notification_ts": notification_ts,
            "from": package_name or "android_notification",
            "source": "android_phone_worker",
            "engine": engine,
            "text": text[:500],
            "fingerprint": _fingerprint("otp-focus", package_name, text, notification_ts),
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


def _maybe_focus_otp_app(auto_cfg: dict, focus_cfg: dict, state_path: Path, state: dict, event: dict) -> None:
    if not focus_cfg.get("enabled", False):
        return
    app_cfg = dict(focus_cfg)
    app_cfg.setdefault("package", "com.whatsapp")
    fp = str(event.get("fingerprint") or event.get("otp") or "")
    if fp and fp == state.get("last_otp_focus_fingerprint"):
        return
    try:
        android._activate_app_adb(auto_cfg, app_cfg, label="whatsapp")
        label = str(event.get("label") or "").strip()
        if not label:
            label = f"otp {event.get('otp')}" if event.get("otp") else "otp notification"
        _log(f"focused WhatsApp for {label}")
        state["last_otp_focus_fingerprint"] = fp
        state["last_otp_focus_at"] = time.time()
        _save_state(state_path, state)
    except Exception as exc:
        _log(f"focus WhatsApp failed: {exc}")


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


def _recent_push_history(state: dict) -> list[dict]:
    raw = state.get("recent_push_history")
    if not isinstance(raw, list):
        return []
    result: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("fingerprint") or "").strip()
        code = str(item.get("code") or "").strip()
        try:
            pushed_at = float(item.get("pushed_at") or 0.0)
        except Exception:
            pushed_at = 0.0
        if not fingerprint and not code:
            continue
        result.append({
            "fingerprint": fingerprint,
            "code": code,
            "pushed_at": pushed_at,
        })
    return result


def _prune_push_history(history: list[dict], *, now: Optional[float] = None, dedupe_window_s: float = 0.0) -> list[dict]:
    current = time.time() if now is None else now
    keep_after = current - max(0.0, dedupe_window_s)
    pruned: list[dict] = []
    for item in history:
        try:
            pushed_at = float(item.get("pushed_at") or 0.0)
        except Exception:
            pushed_at = 0.0
        if dedupe_window_s > 0 and pushed_at and pushed_at < keep_after and not str(item.get("fingerprint") or "").strip():
            continue
        pruned.append({
            "fingerprint": str(item.get("fingerprint") or "").strip(),
            "code": str(item.get("code") or "").strip(),
            "pushed_at": pushed_at,
        })
    if len(pruned) > MAX_PUSH_HISTORY:
        pruned = pruned[-MAX_PUSH_HISTORY:]
    return pruned


def _should_skip_event(event: dict, state: dict, *, first_scan: bool, ignore_existing: bool, dedupe_window_s: float) -> str:
    fp = str(event.get("fingerprint") or "")
    now = float(event.get("ts") or time.time())
    if fp and fp == state.get("last_fingerprint"):
        return "duplicate_fingerprint"
    for item in _recent_push_history(state):
        if fp and fp == item.get("fingerprint"):
            return "duplicate_fingerprint"
    last_code = str(state.get("last_code") or "")
    try:
        last_pushed_event_ts = float(state.get("last_pushed_event_ts") or 0.0)
    except Exception:
        last_pushed_event_ts = 0.0
    if last_pushed_event_ts and now <= last_pushed_event_ts and last_code == str(event.get("otp") or ""):
        return "stale_notification"
    try:
        last_at = float(state.get("last_pushed_at") or 0.0)
    except Exception:
        last_at = 0.0
    if last_code and last_code == str(event.get("otp") or "") and now - last_at < dedupe_window_s:
        return "duplicate_code"
    event_code = str(event.get("otp") or "")
    if event_code and dedupe_window_s > 0:
        for item in _recent_push_history(state):
            code = str(item.get("code") or "")
            try:
                pushed_at = float(item.get("pushed_at") or 0.0)
            except Exception:
                pushed_at = 0.0
            if code and code == event_code and now - pushed_at < dedupe_window_s:
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
    current = time.time()
    state.update({
        "last_fingerprint": event.get("fingerprint") or "",
        "last_code": event.get("otp") or "",
        "last_seen_at": current,
    })
    if pushed:
        state["last_pushed_at"] = current
        state["last_pushed_event_ts"] = float(event.get("ts") or 0.0)
        history = _prune_push_history(
            _recent_push_history(state) + [{
                "fingerprint": event.get("fingerprint") or "",
                "code": event.get("otp") or "",
                "pushed_at": current,
            }],
            now=current,
        )
        state["recent_push_history"] = history
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
    screen_cfg = android._screen_cfg(auto_cfg)
    screen_keepalive_interval_s = float(
        worker_cfg.get("screen_keepalive_interval_s")
        or screen_cfg.get("keepalive_interval_s")
        or 30
    )
    ignore_existing = bool(worker_cfg.get("ignore_existing_on_start", True)) and not args.push_existing
    state_path = _state_file(worker_cfg)
    state = _load_state(state_path)
    url = _push_url(worker_cfg)
    token = _relay_token(worker_cfg)
    otp_focus_cfg = _otp_focus_worker_cfg(worker_cfg)
    unlink_worker_cfg = _gopay_unlink_worker_cfg(worker_cfg)
    auto_unlink_enabled = bool(unlink_worker_cfg.get("enabled", False))
    otp_focus_on_run_log = bool(otp_focus_cfg.get("enabled", False)) and bool(
        otp_focus_cfg.get("focus_on_run_log", True)
    )
    run_log_poll_enabled = auto_unlink_enabled or otp_focus_on_run_log
    run_logs_url = _run_logs_url(worker_cfg, unlink_worker_cfg, otp_focus_cfg) if run_log_poll_enabled else ""
    run_log_poll_interval_s = float(
        otp_focus_cfg.get("run_log_poll_interval_s")
        or unlink_worker_cfg.get("poll_interval_s")
        or interval_s
    )
    run_log_limit = int(otp_focus_cfg.get("run_log_limit") or unlink_worker_cfg.get("log_limit") or 500)
    otp_read_delay_after_run_log_s = float(
        otp_focus_cfg.get("read_delay_after_run_log_trigger_s")
        or worker_cfg.get("otp_read_delay_after_run_log_trigger_s")
        or 0
    )
    otp_push_immediately_after_run_log = bool(
        otp_focus_cfg.get(
            "push_immediately_after_run_log_trigger",
            worker_cfg.get("otp_push_immediately_after_run_log_trigger", False),
        )
    )
    unlink_out_dir = str(unlink_worker_cfg.get("out_dir") or "output/android-gopay-unlink")
    unlink_delay_s = float(unlink_worker_cfg.get("delay_after_trigger_s") or 0)
    unlink_timeout_s = float(unlink_worker_cfg.get("timeout_s") or 120)
    ignore_existing_run_logs = bool(unlink_worker_cfg.get("ignore_existing_run_logs_on_start", True))
    otp_focus_run_log_trigger_strings = _otp_focus_run_log_trigger_strings(otp_focus_cfg)
    trigger_strings = _gopay_unlink_trigger_strings(unlink_worker_cfg)
    try:
        last_run_log_seq = int(state.get("last_run_log_seq") or 0)
    except Exception:
        last_run_log_seq = 0
    try:
        otp_wait_since = float(state.get("last_otp_wait_since") or 0.0)
    except Exception:
        otp_wait_since = 0.0
    try:
        otp_read_after = float(state.get("last_otp_read_after") or 0.0)
    except Exception:
        otp_read_after = 0.0
    otp_wait_active = bool(state.get("otp_wait_active", False))

    android._adb_connect(auto_cfg)
    android._configure_screen_awake(auto_cfg)
    if worker_cfg.get("set_proxy_on_start", True):
        android._set_android_proxy(auto_cfg)

    driver = None
    appium_disabled_until = 0.0
    first_scan = True
    first_run_log_scan = True
    next_run_log_poll_at = 0.0
    last_run_log_error_at = 0.0
    next_screen_keepalive_at = 0.0
    try:
        while True:
            if android._screen_awake_enabled(auto_cfg) and time.time() >= next_screen_keepalive_at:
                android._keep_screen_awake(auto_cfg)
                next_screen_keepalive_at = time.time() + max(5.0, screen_keepalive_interval_s)

            if run_log_poll_enabled and time.time() >= next_run_log_poll_at:
                next_run_log_poll_at = time.time() + max(0.5, run_log_poll_interval_s)
                try:
                    log_payload = _fetch_run_log_payload(
                        run_logs_url,
                        token,
                        since_seq=last_run_log_seq,
                        limit=run_log_limit,
                        timeout=post_timeout_s,
                    )
                    status = log_payload.get("status") if isinstance(log_payload.get("status"), dict) else {}
                    active_otp_wait = bool(status.get("otp_pending"))
                    otp_wait_active = active_otp_wait
                    state["otp_wait_active"] = active_otp_wait
                    if active_otp_wait and not otp_wait_since:
                        otp_wait_since = time.time()
                        state["last_otp_wait_since"] = otp_wait_since
                    if active_otp_wait and otp_read_delay_after_run_log_s > 0 and not otp_read_after:
                        otp_read_after = otp_wait_since + otp_read_delay_after_run_log_s
                        state["last_otp_read_after"] = otp_read_after
                    if not active_otp_wait:
                        otp_read_after = 0.0
                    try:
                        log_count = int(status.get("log_count") or 0)
                    except Exception:
                        log_count = 0
                    if last_run_log_seq and log_count and log_count < last_run_log_seq:
                        last_run_log_seq = 0
                        first_run_log_scan = True
                        log_payload = _fetch_run_log_payload(
                            run_logs_url,
                            token,
                            since_seq=0,
                            limit=run_log_limit,
                            timeout=post_timeout_s,
                        )
                    lines = log_payload.get("lines") if isinstance(log_payload.get("lines"), list) else []
                    if lines:
                        max_seq = max([last_run_log_seq] + [_entry_seq(entry) for entry in lines])
                        allow_active_otp_focus = (
                            first_run_log_scan
                            and ignore_existing_run_logs
                            and active_otp_wait
                            and otp_focus_on_run_log
                        )
                        if first_run_log_scan and ignore_existing_run_logs and not allow_active_otp_focus:
                            last_run_log_seq = max_seq
                            state["last_run_log_seq"] = last_run_log_seq
                            _save_state(state_path, state)
                        else:
                            otp_focus_entry = None
                            if otp_focus_on_run_log:
                                otp_focus_entry = _latest_matching_entry(
                                    lines,
                                    _log_entry_matches_otp_focus_trigger,
                                    otp_focus_run_log_trigger_strings,
                                )
                            trigger_entry = None
                            if auto_unlink_enabled and not (
                                first_run_log_scan and ignore_existing_run_logs
                            ):
                                trigger_entry = _latest_matching_entry(
                                    lines,
                                    _log_entry_matches_unlink_trigger,
                                    trigger_strings,
                                )
                            last_run_log_seq = max_seq
                            state["last_run_log_seq"] = last_run_log_seq
                            if otp_focus_entry is not None:
                                otp_focus_seq = _entry_seq(otp_focus_entry)
                                otp_wait_since = _entry_ts(otp_focus_entry) or time.time()
                                otp_read_after = otp_wait_since + max(0.0, otp_read_delay_after_run_log_s)
                                state["last_otp_focus_run_log_seq"] = otp_focus_seq
                                state["last_otp_focus_run_log_line"] = _entry_line(otp_focus_entry)[:300]
                                state["last_otp_focus_run_log_at"] = time.time()
                                state["last_otp_wait_since"] = otp_wait_since
                                state["last_otp_read_after"] = otp_read_after
                                state["otp_wait_active"] = True
                                otp_wait_active = True
                                _save_state(state_path, state)
                                _log(
                                    f"otp focus trigger seq={otp_focus_seq}: "
                                    f"{_entry_line(otp_focus_entry)[:120]}"
                                )
                                _maybe_focus_otp_app(
                                    auto_cfg,
                                    otp_focus_cfg,
                                    state_path,
                                    state,
                                    _run_log_focus_event(otp_focus_entry),
                                )
                            if trigger_entry is not None:
                                trigger_seq = _entry_seq(trigger_entry)
                                state["last_unlink_trigger_seq"] = trigger_seq
                                state["last_unlink_trigger_line"] = _entry_line(trigger_entry)[:300]
                                state["last_unlink_trigger_at"] = time.time()
                                _save_state(state_path, state)
                                _log(f"gopay unlink trigger seq={trigger_seq}: {_entry_line(trigger_entry)[:120]}")
                                if unlink_delay_s > 0:
                                    time.sleep(unlink_delay_s)
                                try:
                                    if driver is not None:
                                        driver.quit()
                                except Exception:
                                    pass
                                driver = None
                                try:
                                    android._keep_screen_awake(auto_cfg)
                                    android._activate_app_adb(
                                        auto_cfg,
                                        android._section(auto_cfg, "gopay_unlink"),
                                        label="gopay",
                                    )
                                    _log("focused GoPay for unlink")
                                except Exception as exc:
                                    _log(f"focus GoPay before unlink failed: {exc}")
                                try:
                                    rc = _run_configured_unlink(
                                        str(args.config),
                                        unlink_out_dir,
                                        timeout_s=unlink_timeout_s,
                                    )
                                except Exception as exc:
                                    rc = 2
                                    _log(f"gopay unlink flow failed: {exc}")
                                else:
                                    if rc == 0:
                                        _log("gopay unlink flow completed")
                                    else:
                                        _log(f"gopay unlink flow failed rc={rc}")
                                state["last_unlink_at"] = time.time()
                                state["last_unlink_rc"] = rc
                            _save_state(state_path, state)
                        first_run_log_scan = False
                    elif first_run_log_scan:
                        first_run_log_scan = False
                except Exception as exc:
                    now = time.time()
                    if now - last_run_log_error_at >= skip_log_interval_s:
                        _log(str(exc) if isinstance(exc, PhoneWorkerError) else f"run log poll failed: {exc}")
                        last_run_log_error_at = now

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

            events = _extract_otp_events(payload, otp_cfg, engine=engine) if payload is not None else []
            focus_hint = (
                _extract_otp_focus_hint(payload, otp_cfg, otp_focus_cfg, engine=engine)
                if payload is not None
                else None
            )
            if focus_hint is not None and not (first_scan and ignore_existing):
                _maybe_focus_otp_app(auto_cfg, otp_focus_cfg, state_path, state, focus_hint)

            if not events:
                if args.once:
                    _log("no otp notification found")
                    return 1
                first_scan = False
                time.sleep(max(0.5, interval_s))
                continue

            if otp_wait_active and otp_read_after and time.time() < otp_read_after:
                wait_s = max(0.0, otp_read_after - time.time())
                delay_key = f"otp-read-after:{int(otp_read_after)}"
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
                    _log(f"wait {wait_s:.1f}s after OTP request before reading notification")
                    state["last_delay_log_key"] = delay_key
                    state["last_delay_log_at"] = now
                    _save_state(state_path, state)
                first_scan = False
                time.sleep(max(0.5, min(interval_s, wait_s)))
                continue

            event = None
            reason = ""
            skipped: list[tuple[dict, str]] = []
            for candidate in events:
                candidate_reason = _should_skip_event(
                    candidate,
                    state,
                    first_scan=first_scan,
                    ignore_existing=ignore_existing,
                    dedupe_window_s=dedupe_window_s,
                )
                if args.force:
                    candidate_reason = ""
                if candidate_reason == "initial_existing_notification" and otp_wait_active:
                    event_ts = (
                        _coerce_epoch(candidate.get("notification_ts"))
                        or _coerce_epoch(candidate.get("ts"))
                        or time.time()
                    )
                    if not otp_wait_since or event_ts >= otp_wait_since - 5.0:
                        candidate_reason = ""
                if not candidate_reason:
                    event = candidate
                    break
                skipped.append((candidate, candidate_reason))
            if event is None and skipped:
                event, reason = skipped[0]
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

            _maybe_focus_otp_app(auto_cfg, otp_focus_cfg, state_path, state, event)

            bypass_push_delay = bool(otp_wait_active and otp_push_immediately_after_run_log)
            delay_remaining_s = 0.0 if (args.force or bypass_push_delay) else _push_delay_remaining(event, push_delay_s)
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
