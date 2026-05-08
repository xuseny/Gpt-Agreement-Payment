"""邮箱服务。

支持两条 OTP 路径：
  1. Cloudflare Email Worker → KV
  2. 预置 Hotmail 邮箱池（`邮箱----收件api`）→ mailapi 轮询
"""
from __future__ import annotations

import logging
import random
import string
from pathlib import Path
from typing import Any, Optional

from cf_kv_otp_provider import CloudflareKVOtpProvider
from mailapi_otp_provider import HotmailPool, MailApiOtpProvider

logger = logging.getLogger(__name__)


class MailProvider:
    """统一邮箱分配 + OTP 读取入口。"""

    HOTMAIL_SOURCES = {"hotmail", "hotmail_pool", "mailapi", "pool"}
    CF_SOURCES = {"cf", "cf_kv", "cloudflare", "cloudflare_kv", "kv"}

    def __init__(self, mail_cfg: Any = None):
        self.mail_cfg = self._normalize_mail_cfg(mail_cfg)
        self.catch_all_domain = str(self.mail_cfg.get("catch_all_domain") or "").strip()
        self.source = str(self.mail_cfg.get("source") or "").strip().lower()
        self.hotmail_pool_cfg = (
            self.mail_cfg.get("hotmail_pool")
            if isinstance(self.mail_cfg.get("hotmail_pool"), dict)
            else {}
        )
        self._config_dir = str(self.mail_cfg.get("_config_dir") or "").strip()
        self._hotmail_pool_obj: Optional[HotmailPool] = None
        self._reuse_email: Optional[str] = None  # 兼容 register-only resume

    @staticmethod
    def _normalize_mail_cfg(mail_cfg: Any) -> dict:
        if mail_cfg is None:
            return {}
        if isinstance(mail_cfg, str):
            return {"catch_all_domain": mail_cfg}
        if isinstance(mail_cfg, dict):
            return dict(mail_cfg)

        out = {}
        for key in (
            "source",
            "catch_all_domain",
            "catch_all_domains",
            "auto_provision",
            "hotmail_pool",
            "_config_dir",
        ):
            if hasattr(mail_cfg, key):
                out[key] = getattr(mail_cfg, key)
        return out

    def _resolve_path(self, raw_path: str) -> Path:
        path = Path(str(raw_path or "")).expanduser()
        if path.is_absolute():
            return path
        if self._config_dir:
            return (Path(self._config_dir) / path).resolve()
        return path.resolve()

    def _hotmail_pool_enabled(self) -> bool:
        cfg = self.hotmail_pool_cfg
        if not isinstance(cfg, dict) or not cfg:
            return False
        if cfg.get("enabled") is False:
            return False
        return bool(cfg.get("path") or cfg.get("pool_path") or cfg.get("file"))

    def _hotmail_pool(self) -> HotmailPool:
        if self._hotmail_pool_obj is not None:
            return self._hotmail_pool_obj
        cfg = self.hotmail_pool_cfg or {}
        raw_pool_path = cfg.get("path") or cfg.get("pool_path") or cfg.get("file") or ""
        if not str(raw_pool_path).strip():
            raise RuntimeError("mail.hotmail_pool.path 未配置")
        pool_path = self._resolve_path(str(raw_pool_path))
        raw_state_path = cfg.get("state_path") or cfg.get("cursor_path") or ""
        state_path = self._resolve_path(str(raw_state_path)) if str(raw_state_path).strip() else None
        delimiter = str(cfg.get("delimiter") or "----")
        lock_timeout_s = float(cfg.get("lock_timeout_s") or 30.0)
        lock_stale_timeout_s = float(cfg.get("lock_stale_timeout_s") or 300.0)
        self._hotmail_pool_obj = HotmailPool(
            pool_path,
            state_path=state_path,
            delimiter=delimiter,
            lock_timeout_s=lock_timeout_s,
            lock_stale_timeout_s=lock_stale_timeout_s,
        )
        return self._hotmail_pool_obj

    def _should_use_hotmail_pool(self, email_addr: str = "") -> bool:
        if self.source in self.HOTMAIL_SOURCES:
            return True
        if self.source in self.CF_SOURCES:
            return False
        if not self._hotmail_pool_enabled():
            return False
        target = str(email_addr or "").strip().lower()
        if target:
            return self._hotmail_pool().lookup(target) is not None
        return True

    def _build_hotmail_provider(self) -> MailApiOtpProvider:
        cfg = self.hotmail_pool_cfg or {}
        return MailApiOtpProvider(
            poll_interval_s=float(cfg.get("poll_interval_s") or 3.0),
            request_timeout_s=float(cfg.get("request_timeout_s") or 20.0),
            issued_after_grace_s=float(cfg.get("issued_after_grace_s") or 45.0),
        )

    @staticmethod
    def _random_name() -> str:
        letters1 = "".join(random.choices(string.ascii_lowercase, k=5))
        numbers = "".join(random.choices(string.digits, k=random.randint(1, 3)))
        letters2 = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
        return letters1 + numbers + letters2

    def create_mailbox(self) -> str:
        """生成注册邮箱（也可复用 _reuse_email）。"""
        if self._reuse_email:
            addr = self._reuse_email
            self._reuse_email = None
            logger.info(f"复用邮箱: {addr}")
            return addr
        if self._should_use_hotmail_pool():
            entry = self._hotmail_pool().allocate_next()
            logger.info(f"邮箱已分配: {entry.email} (路径: Hotmail pool → mailapi)")
            return entry.email
        if not self.catch_all_domain:
            raise RuntimeError(
                "MailProvider.create_mailbox: catch_all_domain 未配置；"
                "CF Email Worker 路径需要 catch-all 子域（在 zone 内），"
                "Hotmail 路径需要 mail.hotmail_pool.path"
            )
        addr = f"{self._random_name()}@{self.catch_all_domain}"
        logger.info(f"邮箱已创建: {addr} (路径: CF Email Worker → KV)")
        return addr

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        """阻塞等 OTP。

        失败抛 TimeoutError 或 RuntimeError。原 IMAP 路径已删除。
        """
        if self._should_use_hotmail_pool(email_addr):
            entry = self._hotmail_pool().lookup(email_addr)
            if entry is None:
                raise RuntimeError(
                    f"Hotmail pool 未找到邮箱 {email_addr}；"
                    "请确认 pool 文件里存在对应 `邮箱----收件api`"
                )
            logger.info(f"[mail] 走 Hotmail pool 取 OTP -> {email_addr} (timeout={timeout}s)")
            provider = self._build_hotmail_provider()
            return provider.wait_for_otp(
                email_addr,
                entry.api_url,
                timeout=timeout,
                issued_after=issued_after,
            )

        logger.info(f"[mail] 走 CF KV 取 OTP -> {email_addr} (timeout={timeout}s)")
        provider = CloudflareKVOtpProvider.from_env_or_secrets()
        return provider.wait_for_otp(email_addr, timeout=timeout, issued_after=issued_after)
