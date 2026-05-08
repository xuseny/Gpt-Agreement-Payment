"""Hotmail pool + mail API OTP provider."""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


logger = logging.getLogger(__name__)

KNOWN_NON_OTP_VALUES = {"353740", "202123"}
DEFAULT_DELIMITER = "----"

_OTP_CONTEXT_PATTERNS = (
    re.compile(
        r"(?:code(?:\s*is)?|verification|one[-\s]*time|verify|验证码|otp|chatgpt|openai|temporary)"
        r"[^\d]{0,80}(\d{6})\b",
        re.IGNORECASE,
    ),
    re.compile(r">\s*(\d{6})\s*<"),
    re.compile(r"(?<!\d)(\d{6})(?!\d)"),
)
_HTML_DATE_PATTERNS = (
    re.compile(r"<strong>\s*日期:\s*</strong>\s*([^<\r\n]+)", re.IGNORECASE),
    re.compile(r'"date"\s*:\s*"([^"]+)"', re.IGNORECASE),
)


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _parse_ts(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        raw = float(value)
        return raw / 1000.0 if raw > 1e10 else raw
    text = _clean_text(value)
    if not text:
        return None
    if text.isdigit():
        raw = float(text)
        return raw / 1000.0 if raw > 1e10 else raw
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _subject_confirms_otp(subject: str, otp: str) -> bool:
    if not subject or not otp:
        return False
    return bool(
        re.search(
            rf"(?:code(?:\s*is)?|verification|one[-\s]*time|verify|验证码|otp|chatgpt|openai)[^\d]{{0,40}}{re.escape(otp)}\b",
            subject,
            re.IGNORECASE,
        )
    )


def _extract_otp_from_text(text: str) -> str:
    text = _clean_text(text)
    if not text:
        return ""
    for pattern in _OTP_CONTEXT_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        otp = _clean_text(match.group(1) if match.groups() else match.group(0))
        if otp and otp not in KNOWN_NON_OTP_VALUES:
            return otp
    return ""


def _walk_string_values(value: Any, *, depth: int = 0, max_depth: int = 6) -> list[str]:
    if depth > max_depth or value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_walk_string_values(item, depth=depth + 1, max_depth=max_depth))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_walk_string_values(item, depth=depth + 1, max_depth=max_depth))
        return out
    return []


def _extract_candidate_from_json_item(item: Any) -> Optional[dict]:
    if item is None:
        return None
    if isinstance(item, str):
        otp = _extract_otp_from_text(item)
        return {"otp": otp, "ts": None, "subject": "", "source": "mailapi_text"} if otp else None
    if not isinstance(item, dict):
        return None

    subject = _clean_text(item.get("subject") or item.get("title") or item.get("name"))
    ts = _parse_ts(
        item.get("date")
        or item.get("received_at")
        or item.get("created_at")
        or item.get("ts")
        or item.get("timestamp")
    )

    for key in ("verification_code", "verificationCode", "otp", "code"):
        otp = _clean_text(item.get(key))
        if otp and otp not in KNOWN_NON_OTP_VALUES:
            return {"otp": otp, "ts": ts, "subject": subject, "source": f"mailapi_json:{key}"}

    for text in _walk_string_values(item):
        otp = _extract_otp_from_text(text)
        if otp:
            return {"otp": otp, "ts": ts, "subject": subject, "source": "mailapi_json:text"}
    return None


def _extract_candidate_from_json_payload(payload: Any) -> Optional[dict]:
    if isinstance(payload, list):
        candidates = [cand for cand in (_extract_candidate_from_json_item(item) for item in payload) if cand]
        if not candidates:
            return None
        candidates.sort(key=lambda item: float(item.get("ts") or 0.0), reverse=True)
        return candidates[0]
    return _extract_candidate_from_json_item(payload)


def _extract_candidate_from_html(text: str) -> Optional[dict]:
    text = _clean_text(text)
    if not text:
        return None
    otp = _extract_otp_from_text(text)
    if not otp:
        return None
    ts = None
    for pattern in _HTML_DATE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        ts = _parse_ts(match.group(1))
        if ts is not None:
            break
    subject_match = re.search(r"<strong>\s*主题:\s*</strong>\s*([^<\r\n]+)", text, re.IGNORECASE)
    subject = _clean_text(subject_match.group(1)) if subject_match else ""
    return {"otp": otp, "ts": ts, "subject": subject, "source": "mailapi_html"}


def _url_with_type(url: str, type_value: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query["type"] = [type_value]
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


@dataclass(frozen=True)
class HotmailPoolEntry:
    email: str
    api_url: str
    line_no: int


class _ExclusiveFileLock:
    def __init__(self, path: Path, *, acquire_timeout_s: float = 30.0, stale_timeout_s: float = 300.0):
        self.path = path
        self.acquire_timeout_s = max(1.0, float(acquire_timeout_s))
        self.stale_timeout_s = max(30.0, float(stale_timeout_s))
        self.acquired = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.acquire_timeout_s
        while time.time() < deadline:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as fw:
                    fw.write(f"{os.getpid()} {time.time():.0f}\n")
                self.acquired = True
                return self
            except FileExistsError:
                try:
                    stat = self.path.stat()
                    if time.time() - stat.st_mtime > self.stale_timeout_s:
                        self.path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                time.sleep(0.2)
        raise TimeoutError(f"Hotmail pool lock timeout: {self.path}")

    def __exit__(self, exc_type, exc, tb):
        if self.acquired:
            try:
                self.path.unlink(missing_ok=True)
            except Exception:
                pass


class HotmailPool:
    def __init__(
        self,
        pool_path: Path,
        *,
        state_path: Optional[Path] = None,
        delimiter: str = DEFAULT_DELIMITER,
        lock_timeout_s: float = 30.0,
        lock_stale_timeout_s: float = 300.0,
    ):
        self.pool_path = pool_path
        self.state_path = state_path or pool_path.with_suffix(pool_path.suffix + ".state.json")
        self.lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
        self.delimiter = delimiter or DEFAULT_DELIMITER
        self.lock_timeout_s = lock_timeout_s
        self.lock_stale_timeout_s = lock_stale_timeout_s

    def _read_entries(self) -> list[HotmailPoolEntry]:
        if not self.pool_path.exists():
            raise RuntimeError(f"Hotmail pool file not found: {self.pool_path}")
        raw_lines = self.pool_path.read_text(encoding="utf-8-sig").splitlines()
        entries: list[HotmailPoolEntry] = []
        invalid_lines: list[int] = []
        for idx, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if self.delimiter not in line:
                invalid_lines.append(idx)
                continue
            email, api_url = line.split(self.delimiter, 1)
            email = _clean_text(email).lower()
            api_url = _clean_text(api_url)
            if not email or not api_url:
                invalid_lines.append(idx)
                continue
            entries.append(HotmailPoolEntry(email=email, api_url=api_url, line_no=idx))
        if invalid_lines:
            raise RuntimeError(
                f"Hotmail pool invalid line(s): {','.join(str(i) for i in invalid_lines)} "
                f"(expected `email{self.delimiter}api_url`)"
            )
        if not entries:
            raise RuntimeError(f"Hotmail pool is empty: {self.pool_path}")
        return entries

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return {"next_index": 0}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {"next_index": 0}
        if not isinstance(data, dict):
            return {"next_index": 0}
        return data

    def _save_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    def lookup(self, email_addr: str) -> Optional[HotmailPoolEntry]:
        target = _clean_text(email_addr).lower()
        if not target:
            return None
        for entry in self._read_entries():
            if entry.email == target:
                return entry
        return None

    def allocate_next(self) -> HotmailPoolEntry:
        with _ExclusiveFileLock(
            self.lock_path,
            acquire_timeout_s=self.lock_timeout_s,
            stale_timeout_s=self.lock_stale_timeout_s,
        ):
            entries = self._read_entries()
            state = self._load_state()
            try:
                next_index = int(state.get("next_index", 0) or 0)
            except Exception:
                next_index = 0
            entry = entries[next_index % len(entries)]
            state["next_index"] = next_index + 1
            state["last_allocated_email"] = entry.email
            state["last_allocated_line"] = entry.line_no
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._save_state(state)
            return entry


class MailApiOtpProvider:
    def __init__(
        self,
        *,
        poll_interval_s: float = 3.0,
        request_timeout_s: float = 20.0,
        issued_after_grace_s: float = 45.0,
    ):
        self.poll_interval_s = max(0.5, float(poll_interval_s))
        self.request_timeout_s = max(3.0, float(request_timeout_s))
        self.issued_after_grace_s = max(0.0, float(issued_after_grace_s))
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _fetch_text(self, url: str) -> tuple[str, str]:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0",
            },
            method="GET",
        )
        with self._opener.open(req, timeout=self.request_timeout_s) as resp:
            raw = resp.read()
            return raw.decode("utf-8", errors="replace"), _clean_text(resp.headers.get("Content-Type"))

    def _extract_candidate(self, body: str, content_type: str) -> Optional[dict]:
        text = _clean_text(body)
        if not text:
            return None
        maybe_json = (
            content_type.lower().startswith("application/json")
            or text.startswith("{")
            or text.startswith("[")
        )
        if maybe_json:
            try:
                payload = json.loads(text)
            except Exception:
                payload = None
            if payload is not None:
                candidate = _extract_candidate_from_json_payload(payload)
                if candidate:
                    return candidate
        return _extract_candidate_from_html(text)

    def wait_for_otp(
        self,
        email_addr: str,
        api_url: str,
        *,
        timeout: int = 180,
        issued_after: Optional[float] = None,
    ) -> str:
        key = _clean_text(email_addr).lower()
        if not key:
            raise RuntimeError("MailApiOtpProvider.wait_for_otp: email_addr is required")
        if not _clean_text(api_url):
            raise RuntimeError(f"MailApiOtpProvider.wait_for_otp: api_url missing for {key}")

        if issued_after is None:
            issued_after = time.time()
        accept_threshold_s = float(issued_after) - self.issued_after_grace_s
        deadline = time.time() + max(1, int(timeout))
        start = time.time()
        polls = 0
        last_log_at = 0.0
        urls = [api_url]
        html_url = _url_with_type(api_url, "html")
        if html_url not in urls:
            urls.append(html_url)

        logger.info(
            f"[mailapi] 等 OTP key={key} timeout={timeout}s "
            f"(issued_after={issued_after:.0f} grace={self.issued_after_grace_s:.0f}s)"
        )

        while time.time() < deadline:
            polls += 1
            for current_url in urls:
                try:
                    body, content_type = self._fetch_text(current_url)
                except urllib.error.HTTPError as e:
                    body = e.read().decode(errors="replace")[:200]
                    logger.warning(f"[mailapi] HTTP {e.code} key={key} url={current_url} body={body}")
                    continue
                except Exception as e:
                    logger.warning(f"[mailapi] 轮询异常 key={key} url={current_url}: {e}")
                    continue

                candidate = self._extract_candidate(body, content_type)
                if not candidate:
                    continue

                otp = _clean_text(candidate.get("otp"))
                ts_s = _parse_ts(candidate.get("ts"))
                subject = _clean_text(candidate.get("subject"))
                if not otp:
                    continue
                if otp in KNOWN_NON_OTP_VALUES and not _subject_confirms_otp(subject, otp):
                    logger.warning(f"[mailapi] 命中疑似非 OTP 值={otp} key={key}，忽略")
                    continue
                if ts_s is not None and ts_s < accept_threshold_s:
                    logger.info(
                        f"[mailapi] 命中旧 OTP key={key} otp={otp} ts={ts_s:.0f} "
                        f"< threshold={accept_threshold_s:.0f}，忽略"
                    )
                    continue

                elapsed = time.time() - start
                logger.info(
                    f"[mailapi] 收到 OTP={otp} key={key} poll#{polls} elapsed={elapsed:.1f}s "
                    f"source={candidate.get('source')}"
                )
                return otp

            now = time.time()
            if now - last_log_at >= 30:
                logger.info(f"[mailapi] 轮询中 key={key} 已等 {int(now - start)}s polls={polls}")
                last_log_at = now
            time.sleep(self.poll_interval_s)

        raise TimeoutError(f"MailApiOtpProvider: 等 OTP 超时 {timeout}s key={key}")
