"""协议进程只向 Nest 要验证码，不接收邮箱 refresh token 或密码。"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from app.cancel import raise_if_cancelled

# Nest 找回取件换 token 和拉信共用 40 秒。这里多留 10 秒读完响应。
MAILBOX_HTTP_TIMEOUT = 50


class NestMailbox:
    def __init__(self, account_id: int, email: str, base_url: str, token: str) -> None:
        self.account_id = int(account_id)
        self.email = email
        self.base_url = str(base_url or "").rstrip("/")
        self.token = token
        self._seen: set[str] = set()
        self._baseline_loaded = False
        self._baseline_failed = False

    def snapshot_openai_message_ids(self, email: str) -> set[str]:
        return self._load_baseline()

    def capture_openai_baseline(self, email: str, quiet: bool = False) -> set[str]:
        return self._load_baseline()

    def wait_for_new_verification_code(self, email: str, timeout: int = 150, exclude_codes=None, exclude_message_ids=None) -> str:
        return self._wait(timeout, exclude_codes, exclude_message_ids)

    def wait_for_verification_code(self, email: str, timeout: int = 150, **kwargs) -> str:
        return self._wait(timeout, kwargs.get("exclude_codes"), kwargs.get("exclude_message_ids"))

    def _load_baseline(self) -> set[str]:
        if self._baseline_loaded:
            return set(self._seen)
        for _ in range(2):
            ids = self._post_ids()
            if ids is not None:
                self._seen.update(ids)
                self._baseline_failed = False
                self._baseline_loaded = True
                return set(self._seen)
        self._baseline_failed = True
        self._baseline_loaded = True
        return set()

    def _wait(self, timeout: int, exclude_codes, exclude_message_ids) -> str:
        if not self._baseline_loaded:
            self._load_baseline()
        if self._baseline_failed:
            return ""
        deadline = time.time() + max(1, int(timeout or 150))
        excluded = {str(item) for item in (exclude_message_ids or []) if item}
        excluded.update(self._seen)
        banned = {str(item) for item in (exclude_codes or []) if item}
        while time.time() < deadline:
            raise_if_cancelled()
            found = self._post(excluded)
            if found:
                code, message_id = found
                if code not in banned:
                    self._seen.add(message_id)
                    return code
                excluded.add(message_id)
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            time.sleep(min(5, remaining))
        return ""

    def _post_ids(self):
        payload = json.dumps(
            {"accountId": self.account_id, "email": self.email, "baseline": True},
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/internal/mailbox/otp",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=MAILBOX_HTTP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8") or "{}")
        except Exception:
            return None
        if not isinstance(data, dict) or not data.get("ok"):
            return None
        raw = json.dumps(data)
        if any(secret in raw for secret in ("refreshToken", "password", "clientId")):
            return None
        ids = data.get("ids")
        if not isinstance(ids, list):
            return None
        return {str(item) for item in ids if item}

    def _post(self, excluded: set[str]):
        payload = json.dumps(
            {"accountId": self.account_id, "email": self.email, "excludeIds": sorted(excluded)},
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/internal/mailbox/otp",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=MAILBOX_HTTP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError:
            return None
        except Exception:
            return None
        if not isinstance(data, dict) or not data.get("ok"):
            return None
        code = str(data.get("code") or "")
        message_id = str(data.get("id") or "")
        if not code or not message_id:
            return None
        if any(secret in json.dumps(data) for secret in ("refreshToken", "password", "clientId")):
            return None
        return code, message_id
