#!/usr/bin/env python3
"""内部协议服务。没有公开页面，没有数据库，也不打印口令或 session。"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from team_http import TeamCallError, assert_egress_allowed, require_socks

ROOT = Path(__file__).resolve().parent
TOKEN = os.environ.get("PROTOCOL_WORKER_TOKEN", "")
HOST = os.environ.get("PROTOCOL_WORKER_HOST", "0.0.0.0")
PORT = int(os.environ.get("PROTOCOL_WORKER_PORT", "8080"))
CHATGPT = "https://chatgpt.com"
AUTH = "https://auth.openai.com"
MAX_BODY = 2_000_000
PREMIUM_SEAT = "default"
_bound = threading.local()


def fail(code: str, message: str, status: int = 400, **extra):
    body = {"ok": False, "code": code, "message": message}
    body.update(extra)
    return status, body


def error_payload(error: TeamCallError):
    extra = {"inviteSent": True} if getattr(error, "invite_sent", False) else {}
    return fail(error.code, str(error), **extra)


def ok(**extra):
    body = {"ok": True, "code": "OK", "message": ""}
    body.update(extra)
    return 200, body


DOCUMENTED_CLIENT_HEADERS = (
    "oai-client-build-number",
    "oai-client-version",
    "oai-session-id",
    "x-oai-is-client-observation",
    "x-oai-is-pending-updates",
)


def session_access(session: dict) -> str:
    token = session.get("accessToken") or session.get("access_token") or ""
    if not isinstance(token, str) or not token.strip():
        raise TeamCallError("BAD_INPUT", "session 里没有 accessToken")
    return token.strip()


SESSION_COOKIE = "__Secure-next-auth.session-token"


def session_token_value(session) -> str:
    if not isinstance(session, dict):
        return ""
    for key in ("sessionToken", "session_token"):
        value = session.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def replayable_cookies(session: dict) -> bool:
    raw = session.get("cookies") if isinstance(session, dict) else None
    if isinstance(raw, list) and any(
        isinstance(item, dict) and str(item.get("name") or "").strip() and str(item.get("value") or "").strip()
        for item in raw
    ):
        return True
    return bool(session_token_value(session))


def set_cookie(http, name: str, value: str, domain: str = "chatgpt.com") -> None:
    jar = getattr(http, "cookies", None)
    if jar is not None and hasattr(jar, "set"):
        try:
            jar.set(name, value, domain=domain)
        except TypeError:
            jar.set(name, value)
        return
    if not isinstance(jar, dict):
        jar = {}
        try:
            setattr(http, "cookies", jar)
        except Exception:
            return
    jar[name] = value


def attach_living_session(http, session: dict) -> None:
    raw = session.get("cookies") if isinstance(session, dict) else None
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("name") and item.get("value"):
                set_cookie(http, str(item["name"]), str(item["value"]), str(item.get("domain") or "chatgpt.com"))
    token = session_token_value(session)
    if token:
        set_cookie(http, SESSION_COOKIE, token, ".chatgpt.com")
    if isinstance(session, dict):
        remember_client_headers(http, session.get("headers"))
        remember_client_headers(http, session.get("clientHeaders"))


def living_access(http, session: dict, workspace_id: str) -> str:
    attach_living_session(http, session)
    if replayable_cookies(session):
        try:
            refreshed = session_payload(http, "", workspace_id)
            token = str(refreshed.get("accessToken") or refreshed.get("access_token") or "")
            if token:
                return token
        except TeamCallError as error:
            if error.code in ("SESSION_EXPIRED", "EGRESS_BLOCKED"):
                raise
    return session_access(session)


def is_html(response) -> bool:
    kind = (response.headers.get("content-type") or "").lower()
    text = response.text or ""
    return "text/html" in kind or text.lstrip().startswith("<")


def read_json(response):
    if is_html(response):
        raise TeamCallError("EGRESS_BLOCKED", "出口被拦截，已停止")
    try:
        data = response.json()
    except Exception as error:
        raise TeamCallError("UPSTREAM", "上游没有返回可解析结果") from error
    if not isinstance(data, dict) and not isinstance(data, list):
        raise TeamCallError("UPSTREAM", "上游没有返回可解析结果")
    return data


def header_value(http, name: str) -> str:
    headers = getattr(http, "headers", None)
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name.lower() and value:
            return str(value)
    return ""


def remember_client_headers(http, source) -> None:
    if http is None or not isinstance(source, dict):
        return
    picked = {}
    for name in DOCUMENTED_CLIENT_HEADERS:
        for key, value in source.items():
            if str(key).lower() == name and value:
                picked[name] = str(value)
                break
    if not picked:
        return
    headers = getattr(http, "headers", None)
    if isinstance(headers, dict):
        for name, value in picked.items():
            if not header_value(http, name):
                headers[name] = value
        return
    current = getattr(http, "client_headers", None)
    if not isinstance(current, dict):
        current = {}
        try:
            setattr(http, "client_headers", current)
        except Exception:
            return
    current.update({name: value for name, value in picked.items() if name not in current})


def stable_device_id(http) -> str:
    if http is None:
        return str(uuid.uuid4())
    existing = str(getattr(http, "oai_device_id", "") or "")
    if existing:
        return existing
    from_header = header_value(http, "oai-device-id")
    generated = from_header or str(uuid.uuid4())
    try:
        setattr(http, "oai_device_id", generated)
    except Exception:
        pass
    return generated


def browser_headers(token: str, workspace_id: str, target_path: str, referer: str, http=None) -> dict:
    headers = {
        "Chatgpt-Account-Id": workspace_id,
        "Origin": CHATGPT,
        "Referer": referer,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Priority": "u=1, i",
        "oai-device-id": stable_device_id(http),
        "x-openai-target-path": target_path,
        "x-openai-target-route": target_path,
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    language = header_value(http, "Accept-Language").split(",")[0].split(";")[0].strip()
    if language:
        headers["oai-language"] = language
    agent = header_value(http, "User-Agent")
    if agent:
        headers["User-Agent"] = agent
    for name in DOCUMENTED_CLIENT_HEADERS:
        value = header_value(http, name)
        if not value and http is not None:
            client = getattr(http, "client_headers", None)
            if isinstance(client, dict):
                for key, item in client.items():
                    if str(key).lower() == name and item:
                        value = str(item)
                        break
        if value:
            headers[name] = value
    return headers


def open_session(proxy: str):
    from vendor.lib.http_client import create_http_session
    http = create_http_session(require_socks(proxy), impersonate="chrome136")
    if not getattr(http, "oai_device_id", ""):
        http.oai_device_id = str(uuid.uuid4())
    headers = getattr(http, "headers", None)
    if isinstance(headers, dict) and not header_value(http, "Accept-Language"):
        headers["Accept-Language"] = "en-US,en;q=0.9"
    return http


def saved_device_id(body, session=None) -> str:
    device = str((body or {}).get("deviceId") or "").strip()
    if not device and isinstance(session, dict):
        device = str(session.get("oaiDeviceId") or session.get("oai_device_id") or "").strip()
    return device


def apply_saved_device(http, body, session=None) -> None:
    device = saved_device_id(body, session)
    if not device:
        return
    try:
        http.oai_device_id = device
    except Exception:
        pass


def bind_device(http, body, session=None) -> None:
    apply_saved_device(http, body, session)
    try:
        _bound.http = http
    except Exception:
        pass


def header_values(headers, name: str) -> list:
    if headers is None:
        return []
    for method in ("get_list", "getlist"):
        getter = getattr(headers, method, None)
        if not callable(getter):
            continue
        try:
            found = getter(name)
        except Exception:
            continue
        if found:
            return [str(item) for item in found if str(item).strip()]
    if hasattr(headers, "get"):
        found = headers.get(name) or headers.get(name.title()) or ""
        if isinstance(found, list):
            return [str(item) for item in found if str(item).strip()]
        if found:
            return [str(found)]
    return []


def cookie_items(response):
    if response is None:
        return []
    headers = getattr(response, "headers", None)
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    collected = []
    for source in (headers, raw_headers):
        for method in ("get_list", "getlist"):
            getter = getattr(source, method, None) if source is not None else None
            if not callable(getter):
                continue
            try:
                found = getter("set-cookie")
            except Exception:
                continue
            if found:
                collected.append([str(item) for item in found if str(item).strip()])
    raw = max(collected, key=len) if collected else (header_values(headers, "set-cookie") or header_values(raw_headers, "set-cookie"))
    items = []
    for line in raw:
        part = str(line).split(";", 1)[0]
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name and value:
            items.append({"name": name, "value": value, "domain": ".chatgpt.com"})
    return items


def merge_cookie_items(existing, harvested):
    merged = []
    index = {}
    for item in existing if isinstance(existing, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if not name or not value:
            continue
        index[name] = len(merged)
        merged.append({"name": name, "value": value, "domain": str(item.get("domain") or ".chatgpt.com")})
    for item in harvested:
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if not name or not value:
            continue
        stored = {"name": name, "value": value, "domain": str(item.get("domain") or ".chatgpt.com")}
        if name in index:
            merged[index[name]] = stored
        else:
            index[name] = len(merged)
            merged.append(stored)
    return merged


def remember_refresh(http, data, response=None, *, keep_access=True) -> None:
    if http is None:
        return
    current = getattr(http, "session_refresh", None)
    if not isinstance(current, dict):
        current = {}
    if isinstance(data, dict):
        token = str(data.get("accessToken") or data.get("access_token") or "").strip()
        session_token = str(data.get("sessionToken") or data.get("session_token") or "").strip()
        if keep_access and token:
            current["accessToken"] = token
        if session_token:
            current["sessionToken"] = session_token
    harvested = cookie_items(response)
    for item in harvested:
        if item["name"] == SESSION_COOKIE and item["value"]:
            current["sessionToken"] = item["value"]
        try:
            set_cookie(http, item["name"], item["value"], item.get("domain") or ".chatgpt.com")
        except Exception:
            pass
    if harvested:
        current["cookies"] = merge_cookie_items(current.get("cookies"), harvested)
    device = str(getattr(http, "oai_device_id", "") or "").strip()
    if device:
        current["deviceId"] = device
    try:
        setattr(http, "session_refresh", current)
    except Exception:
        pass


def session_update_from(http):
    if http is None:
        return None
    data = getattr(http, "session_refresh", None)
    if not isinstance(data, dict):
        data = {}
    update = {}
    token = str(data.get("accessToken") or "").strip()
    session_token = str(data.get("sessionToken") or "").strip()
    if token:
        update["accessToken"] = token
    if session_token:
        update["sessionToken"] = session_token
    cookies = data.get("cookies") if isinstance(data.get("cookies"), list) else []
    clean = []
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if name and value:
            clean.append({"name": name, "value": value, "domain": str(item.get("domain") or ".chatgpt.com")})
    if clean:
        update["cookies"] = clean
    device = str(data.get("deviceId") or "").strip()
    if device:
        update["deviceId"] = device
    return update or None


def attach_session_update(http, payload):
    if not isinstance(payload, dict):
        return payload
    update = session_update_from(http)
    if not update:
        return payload
    copied = dict(payload)
    copied["sessionUpdate"] = update
    return copied


class SessionHttp:
    def __init__(self, session):
        self.session = session
        self.session_refresh = {}

    def request(self, method, url, headers=None, json=None, data=None, timeout=60):
        kwargs = {"headers": headers or {}, "timeout": timeout}
        if json is not None:
            kwargs["json"] = json
        if data is not None:
            kwargs["data"] = data
        return self.session.request(method, url, **kwargs)

    def get(self, url, headers=None, timeout=60):
        return self.session.get(url, headers=headers or {}, timeout=timeout)


def real_login(email: str, password: str, totp: str, proxy: str, mailbox_account_id=None):
    from app.config import Settings
    from app.engine import authorize_account
    from app.parsing import AccountLine
    settings = Settings(data_dir=ROOT / ".runtime")
    settings.proxy = proxy or ""
    mail_client = None
    if mailbox_account_id and TOKEN:
        import os
        base = os.environ.get("PROTOCOL_MAILBOX_URL", "").strip()
        if base:
            from app.mailbox_callback import NestMailbox
            mail_client = NestMailbox(int(mailbox_account_id), email, base, TOKEN)
    client, tokens = authorize_account(AccountLine(email, password, totp, ""), settings, mail_client=mail_client)
    session = {
        "client": client,
        "tokens": tokens if isinstance(tokens, dict) else {},
        "email": email,
        "password": password,
        "totp": totp,
        "proxy": proxy,
    }
    if mail_client is not None:
        session["mail_client"] = mail_client
    return session


def real_list(session: dict, proxy: str):
    client = session.get("client")
    tokens = session.get("tokens") if isinstance(session.get("tokens"), dict) else {}
    http = SessionHttp(client.session)
    token = str(tokens.get("access_token") or tokens.get("accessToken") or "")
    path = "/backend-api/accounts/check/v4-2023-04-27"
    response = request_with_retry(http, "GET", f"{CHATGPT}{path}", headers=browser_headers(token, "", path, f"{CHATGPT}/", http))
    text = str(getattr(response, "text", "") or "").lower()
    if response.status_code in (401, 403, 429) or response.status_code >= 500:
        if "deactivated" in text or "banned" in text:
            raise TeamCallError("DEACTIVATED", "账号已停用", response.status_code)
        raise TeamCallError("UPSTREAM", "上游暂时失败", response.status_code)
    return read_json(response)


def mint_workspace_oauth(session: dict, workspace_id: str, proxy: str):
    from app.config import Settings
    from app.engine import authorize_account
    from app.parsing import AccountLine
    email = str((session or {}).get("email") or "").strip()
    password = str((session or {}).get("password") or "")
    totp = str((session or {}).get("totp") or "")
    if not email or not password or not totp:
        return {}
    settings = Settings(data_dir=ROOT / ".runtime")
    settings.proxy = proxy or str((session or {}).get("proxy") or "")
    _client, tokens = authorize_account(
        AccountLine(email, password, totp, ""),
        settings,
        workspace_id=workspace_id,
        mail_client=(session or {}).get("mail_client"),
    )
    return tokens if isinstance(tokens, dict) else {}


def real_exchange(session: dict, workspace_id: str, proxy: str):
    from app.extract import exchange_or_mint

    def exchange(current, workspace, current_proxy):
        client = current.get("client")
        tokens = current.get("tokens") if isinstance(current.get("tokens"), dict) else {}
        http = SessionHttp(client.session)
        token = str(tokens.get("access_token") or tokens.get("accessToken") or "")
        data = exchange_workspace(http, token, workspace)
        return {
            "access_token": str(data.get("accessToken") or data.get("access_token") or "").strip(),
            "refresh_token": str(data.get("refreshToken") or data.get("refresh_token") or "").strip(),
            "id_token": str(data.get("idToken") or data.get("id_token") or "").strip(),
        }

    return exchange_or_mint(session, workspace_id, proxy, exchange, mint_workspace_oauth)


def account_extract(body: dict):
    from app.cancel import ExtractCancelled, cancelled
    from app.extract import run_extract
    mailbox_id = body.get("mailboxAccountId") if str(body.get("otpPolicy") or "") == "reclaim" else None

    def login(email, password, totp, proxy):
        return real_login(email, password, totp, proxy, mailbox_id)

    try:
        result = run_extract(body, login, real_list, real_exchange)
    except ExtractCancelled:
        result = {"ok": False, "temporary": True, "code": "ABORTED", "message": "提取已中断"}
    except Exception as error:
        print(f"[gptcdk-protocol] {type(error).__name__} /internal/account/extract", flush=True)
        result = {"ok": False, "temporary": True, "code": "UPSTREAM", "message": "协议服务处理失败"}
    if not isinstance(result, dict):
        result = {"ok": False, "temporary": True, "code": "UPSTREAM", "message": "协议服务处理失败"}
    if cancelled() and not (result.get("ok") and result.get("accessToken") and result.get("refreshToken")):
        result = {"ok": False, "temporary": True, "code": "ABORTED", "message": "提取已中断"}
    for key in ("password", "proxy", "totp", "session", "sessionUpdate", "cookies"):
        result.pop(key, None)
    return 200, result


def precheck(http) -> None:
    response = http.get(f"{CHATGPT}/cdn-cgi/trace", timeout=30)
    if response.status_code >= 400 or is_html(response):
        raise TeamCallError("EGRESS_BLOCKED", "出口预检失败，已停止")
    assert_egress_allowed(response.text or "")


def request_with_retry(http, method: str, url: str, *, headers: dict, payload=None, form=None):
    delays = (5, 10, 15)
    last = None
    for attempt in range(4):
        response = http.request(method, url, headers=headers, json=payload, data=form, timeout=60)
        last = response
        if response.status_code == 409 and attempt < 3:
            time.sleep(delays[attempt])
            continue
        if response.status_code == 429 and attempt < 3:
            time.sleep(min(30, 3 * (2 ** attempt)))
            continue
        return response
    return last


def classify(response, *, session_call: bool):
    if response.status_code in (401, 403) and not is_html(response):
        code = "SESSION_EXPIRED" if session_call else "AUTH"
        message = "母号 session 已失效，请重新贴一次" if session_call else "登录或出口失败"
        raise TeamCallError(code, message, response.status_code)
    if is_html(response) or response.status_code == 403:
        raise TeamCallError("EGRESS_BLOCKED", "出口被拦截，已停止", response.status_code)
    if response.status_code >= 500:
        raise TeamCallError("UPSTREAM", "上游暂时失败", response.status_code)
    return response


def exchange_workspace(http, personal_token: str, workspace_id: str) -> dict:
    path = "/api/auth/session"
    query = urlencode({
        "exchange_workspace_token": "true",
        "workspace_id": workspace_id,
        "reason": "setCurrentAccountWithoutRedirect",
    })
    headers = browser_headers(personal_token, workspace_id, path, f"{CHATGPT}/", http)
    response = request_with_retry(http, "GET", f"{CHATGPT}{path}?{query}", headers=headers)
    remember_refresh(http, {}, response, keep_access=False)
    response = classify(response, session_call=True)
    data = read_json(response)
    if not isinstance(data, dict) or not (data.get("accessToken") or data.get("access_token")):
        raise TeamCallError("SESSION_EXPIRED", "母号 session 已失效，请重新贴一次")
    remember_refresh(http, data, response, keep_access=False)
    return data


def inspect_session(body: dict):
    session = body.get("session")
    if isinstance(session, str):
        session = json.loads(session)
    if not isinstance(session, dict):
        return fail("BAD_INPUT", "session 不是 JSON")
    proxy = body.get("proxy") or ""
    http = open_session(proxy)
    bind_device(http, body, session)
    precheck(http)
    token = living_access(http, session, "")
    me = classify(request_with_retry(http, "GET", f"{CHATGPT}/backend-api/me", headers=browser_headers(token, "", "/backend-api/me", f"{CHATGPT}/", http)), session_call=True)
    me_data = read_json(me)
    email = ""
    if isinstance(me_data, dict):
        email = str(me_data.get("email") or "")
    check_path = "/backend-api/accounts/check/v4-2023-04-27"
    checked = classify(
        request_with_retry(http, "GET", f"{CHATGPT}{check_path}?timezone_offset_min=-480", headers=browser_headers(token, "", check_path, f"{CHATGPT}/", http)),
        session_call=True,
    )
    data = read_json(checked)
    workspaces = []
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if isinstance(accounts, dict):
        for workspace_id, item in accounts.items():
            account = item.get("account") if isinstance(item, dict) and isinstance(item.get("account"), dict) else item
            if not isinstance(account, dict):
                continue
            plan = str(account.get("plan_type") or "")
            workspaces.append({
                "id": str(workspace_id),
                "name": str(account.get("name") or account.get("structure") or workspace_id),
                "role": str(account.get("account_user_role") or ""),
                "planType": plan,
                "deactivated": bool(account.get("is_deactivated")),
            })
    if not email:
        return fail("SESSION_EXPIRED", "母号 session 已失效，请重新贴一次")
    return ok(email=email, workspaces=workspaces)






def session_payload(http, token: str, workspace_id: str) -> dict:
    response = request_with_retry(
        http,
        "GET",
        f"{CHATGPT}/api/auth/session",
        headers=browser_headers(token, workspace_id, "/api/auth/session", f"{CHATGPT}/", http),
    )
    if response.status_code in (401, 403) or is_html(response):
        remember_refresh(http, {}, response)
        if response.status_code in (401, 403) and not is_html(response):
            raise TeamCallError("SESSION_EXPIRED", "母号 session 已失效，请重新贴一次", response.status_code)
        raise TeamCallError("EGRESS_BLOCKED", "出口被拦截，已停止", response.status_code)
    data = read_json(response)
    if not isinstance(data, dict):
        raise TeamCallError("AUTH", "登录后没有拿到 ChatGPT session")
    remember_refresh(http, data, response)
    return data










ROUTES = {
    "/internal/session/inspect": inspect_session,
    "/internal/account/extract": account_extract,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[gptcdk-protocol] {self.command} {self.path} {args[1] if len(args) > 1 else ''}", flush=True)

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/health":
            self._send(200, {"ok": True})
            return
        self._send(404, {"ok": False, "code": "NOT_FOUND", "message": "没有这个接口"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ROUTES:
            self._send(404, {"ok": False, "code": "NOT_FOUND", "message": "没有这个接口"})
            return
        if not TOKEN or not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
            self._send(401, {"ok": False, "code": "UNAUTHORIZED", "message": "协议服务未授权"})
            return
        length = int(self.headers.get("Content-Length") or "0")
        if length < 0 or length > MAX_BODY:
            self._send(400, {"ok": False, "code": "BAD_INPUT", "message": "请求过大"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            self._send(400, {"ok": False, "code": "BAD_INPUT", "message": "请求不是 JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"ok": False, "code": "BAD_INPUT", "message": "请求不是 JSON"})
            return
        try:
            _bound.http = None
        except Exception:
            pass
        from app.cancel import CancelState, ExtractCancelled, install_cancel, reset_cancel, watch_disconnect
        import threading
        state = CancelState()
        cancel_token = install_cancel(state)
        done = threading.Event()
        watcher = threading.Thread(target=watch_disconnect, args=(self, state, done), daemon=True)
        watcher.start()
        try:
            try:
                status, payload = ROUTES[path](body)
            except TeamCallError as error:
                status, payload = error_payload(error)
            except ExtractCancelled:
                status, payload = 200, {"ok": False, "temporary": True, "code": "ABORTED", "message": "提取已中断"}
            except Exception as error:
                print(f"[gptcdk-protocol] {type(error).__name__} {path}", flush=True)
                status, payload = fail("UPSTREAM", "协议服务处理失败")
        finally:
            done.set()
            watcher.join(0.3)
            reset_cancel(cancel_token)
        http = getattr(_bound, "http", None)
        try:
            _bound.http = None
        except Exception:
            pass
        payload = attach_session_update(http, payload)
        if path == "/internal/account/extract" and isinstance(payload, dict):
            for key in ("password", "proxy", "totp", "session", "sessionUpdate", "cookies"):
                payload.pop(key, None)
            status = 200
        self._send(status if status < 500 else 200, payload)


def main() -> None:
    if not TOKEN:
        print("[gptcdk-protocol] PROTOCOL_WORKER_TOKEN 未配置，Team 调用会拒绝", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
