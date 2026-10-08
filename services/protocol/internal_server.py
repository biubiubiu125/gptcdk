#!/usr/bin/env python3
"""内部协议服务。没有公开页面，没有数据库，也不打印口令或 session。"""

from __future__ import annotations

import hmac
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
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


def mother_kick_error(error: TeamCallError):
    limited = error.code == "RATE_LIMITED" or error.http_status == 429
    if limited:
        return fail(error.code, f"{error.message}，可能被限流", rateLimited=True)
    return fail(error.code, error.message, error.http_status or 400)


def mother_kick_status(status: int):
    if status in (200, 204):
        return ok(temporary=True, rateLimited=True, message="可能被限流")
    if status == 429:
        return fail("RATE_LIMITED", f"退出失败：HTTP {status}，可能被限流", 429, rateLimited=True)
    return fail("UPSTREAM", f"退出失败：HTTP {status}")


def normalize_active_until(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return _active_until_unix(float(value))
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10,13}", text):
        return _active_until_unix(float(text))
    if re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", text, re.IGNORECASE):
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return text


def _active_until_unix(value: float):
    if value <= 0:
        return None
    seconds = value / 1000 if value > 10_000_000_000 else value
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def login_child(email: str, password: str, totp: str, proxy: str, workspace_id: str = ""):
    from app.engine import open_login_session
    client, tokens = open_login_session(email, password, totp, proxy, workspace_id=workspace_id)
    session = client.session
    device = getattr(client, "device_id", "") or getattr(session, "oai_device_id", "") or str(uuid.uuid4())
    session.oai_device_id = device
    return session, tokens if isinstance(tokens, dict) else {}


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


def walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def nested_person(row: dict) -> list:
    found = []
    for key in ("user", "account_user"):
        value = row.get(key)
        if isinstance(value, dict):
            found.append(value)
    return found


def flatten_person(row):
    if not isinstance(row, dict):
        return None
    sources = [row, *nested_person(row)]

    def pick(*names):
        for source in sources:
            for name in names:
                value = source.get(name)
                if value:
                    return str(value)
        return ""

    person_id = pick("id", "user_id")
    email = pick("email", "email_address")
    role = pick("role", "account_user_role")
    if not person_id or not (email or role):
        return None
    return {"id": person_id, "email": email, "role": role}


def people_in(rows) -> list:
    if not isinstance(rows, list):
        return []
    return [person for person in (flatten_person(row) for row in rows) if person]


def page_has_unparsed(data) -> bool:
    lists = []
    if isinstance(data, list):
        lists.append(data)
    elif isinstance(data, dict):
        for key in ("items", "members", "users", "account_users", "data"):
            value = data.get(key)
            if isinstance(value, list):
                lists.append(value)
    for rows in lists:
        for row in rows:
            if not isinstance(row, dict) or flatten_person(row):
                continue
            if nested_person(row):
                return True
            keys = {str(key).lower() for key in row}
            if keys & {"email", "email_address", "role", "account_user_role", "user_id"}:
                return True
    return False


def member_page(data) -> list:
    if isinstance(data, list):
        return people_in(data)
    if not isinstance(data, dict):
        return []
    for key in ("items", "members", "users", "account_users", "data"):
        people = people_in(data.get(key))
        if people:
            return people
    for key, rows in data.items():
        if key in ("items", "members", "users", "account_users", "data", "errors", "errored_emails"):
            continue
        people = people_in(rows)
        if people:
            return people
    return []


def invite_row(row):
    if not isinstance(row, dict):
        return None
    email = str(row.get("email_address") or row.get("email") or "").strip()
    if not email:
        return None
    return {"id": str(row.get("invite_id") or row.get("id") or "").strip(), "email": email}


def invite_lists(data) -> list:
    if isinstance(data, list):
        return [data]
    if not isinstance(data, dict):
        return []
    lists = []
    seen = set()
    for key in ("items", "invites", "members", "users", "account_users", "data"):
        value = data.get(key)
        if isinstance(value, list):
            lists.append(value)
            seen.add(key)
    for key, value in data.items():
        if key in seen or key in ("errors", "errored_emails", "total"):
            continue
        if isinstance(value, list):
            lists.append(value)
    return lists


def invite_page(data) -> list:
    found = []
    seen = set()
    for rows in invite_lists(data):
        for row in rows:
            item = invite_row(row)
            if not item:
                continue
            key = (item["id"], item["email"].lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return found


def invite_page_unparsed(data) -> bool:
    for rows in invite_lists(data):
        for row in rows:
            if not isinstance(row, dict) or invite_row(row):
                continue
            keys = {str(key).lower() for key in row}
            if keys & {"email", "email_address", "invite_id", "id", "role", "account_user_role"}:
                return True
    return False


def member_of(row: dict) -> dict:
    return {
        "id": str(row.get("id") or row.get("user_id") or ""),
        "email": str(row.get("email") or row.get("email_address") or ""),
        "role": str(row.get("role") or row.get("account_user_role") or ""),
    }


def page_total(data):
    if not isinstance(data, dict) or "total" not in data:
        return None
    total = data.get("total")
    if isinstance(total, bool) or total is None:
        return None
    if isinstance(total, int):
        return total
    if isinstance(total, str):
        text = total.strip()
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            return int(text)
    return None


def snapshot(http, token: str, workspace_id: str) -> dict:
    members = {}
    invites = []
    total = None
    truncated = False
    unparsed = False
    page_failed = False
    offset = 0
    while True:
        path = f"/backend-api/accounts/{workspace_id}/users"
        headers = browser_headers(token, workspace_id, path, f"{CHATGPT}/admin/members", http)
        response = classify(
            request_with_retry(http, "GET", f"{CHATGPT}{path}?offset={offset}&limit=100&query=", headers=headers),
            session_call=True,
        )
        if response.status_code >= 400:
            page_failed = True
            break
        data = read_json(response)
        if page_has_unparsed(data):
            unparsed = True
        page = member_page(data)
        for row in page:
            item = member_of(row)
            if item["id"]:
                members[item["id"]] = item
        found = page_total(data)
        if found is not None:
            total = found
        if len(page) < 100:
            break
        offset += 100
        if offset > 5000:
            truncated = True
            break
    path = f"/backend-api/accounts/{workspace_id}/invites"
    invites_truncated = False
    invite_offset = 0
    while True:
        headers = browser_headers(token, workspace_id, path, f"{CHATGPT}/admin/members", http)
        invite_response = classify(
            request_with_retry(http, "GET", f"{CHATGPT}{path}?limit=100&offset={invite_offset}", headers=headers),
            session_call=True,
        )
        if invite_response.status_code >= 400:
            invites_truncated = True
            break
        invite_data = read_json(invite_response)
        if invite_page_unparsed(invite_data):
            invites_truncated = True
        page = invite_page(invite_data)
        for row in page:
            invites.append(row)
        if len(page) < 100:
            break
        invite_offset += 100
        if invite_offset > 5000:
            invites_truncated = True
            break
    sub_path = "/backend-api/subscriptions"
    sub_headers = browser_headers(token, workspace_id, sub_path, f"{CHATGPT}/admin", http)
    sub = classify(
        request_with_retry(http, "GET", f"{CHATGPT}{sub_path}?account_id={workspace_id}", headers=sub_headers),
        session_call=True,
    )
    subscription_read = sub.status_code < 400
    sub_data = read_json(sub) if subscription_read else {}
    if not isinstance(sub_data, (dict, list)):
        sub_data = {}
        subscription_read = False
    seats = None
    will_renew = None
    active_until = None
    for node in walk(sub_data):
        if seats is None and isinstance(node.get("seats_entitled"), int):
            seats = node["seats_entitled"]
        if will_renew is None and isinstance(node.get("will_renew"), bool):
            will_renew = node["will_renew"]
        if active_until is None and node.get("active_until") is not None:
            active_until = normalize_active_until(node.get("active_until"))
    seat_path = f"/backend-api/accounts/{workspace_id}/users/seat_type_counts"
    try:
        classify(
            request_with_retry(
                http,
                "GET",
                f"{CHATGPT}{seat_path}",
                headers=browser_headers(token, workspace_id, seat_path, f"{CHATGPT}/admin", http),
            ),
            session_call=True,
        )
    except TeamCallError:
        pass
    complete = (not page_failed) and (not truncated) and (not unparsed) and total is not None and len(members) == total
    return {
        "complete": complete,
        "members": list(members.values()),
        "invites": invites,
        "invitesTruncated": invites_truncated,
        "seatsEntitled": seats,
        "willRenew": will_renew,
        "activeUntil": active_until,
        "subscriptionRead": subscription_read,
    }


def invite_emails(payload, requested: list[str]) -> tuple[list[str], list[str]]:
    errored = []
    raw_errors = payload.get("errored_emails") if isinstance(payload, dict) else None
    if isinstance(raw_errors, list):
        for item in raw_errors:
            if isinstance(item, str):
                errored.append(item.strip().lower())
            elif isinstance(item, dict):
                email = str(item.get("email") or item.get("email_address") or "").strip().lower()
                if email:
                    errored.append(email)
    raw_ok = payload.get("account_invites") if isinstance(payload, dict) else None
    successes = []
    if isinstance(raw_ok, list):
        for item in raw_ok:
            if isinstance(item, str):
                successes.append(item.strip().lower())
            elif isinstance(item, dict):
                email = str(item.get("email") or item.get("email_address") or "").strip().lower()
                if email:
                    successes.append(email)
    elif isinstance(raw_ok, int):
        wanted = []
        seen = set()
        for item in requested:
            email = str(item).strip().lower()
            if email and email not in seen:
                wanted.append(email)
                seen.add(email)
        failed = [item for item in errored if item in seen]
        if raw_ok == len(wanted) and not failed:
            successes = wanted
        elif failed and raw_ok == len(wanted) - len(set(failed)) and raw_ok >= 0:
            failed_set = set(failed)
            successes = [item for item in wanted if item not in failed_set]
    return successes, errored


def invite_outcome(response, emails: list[str]) -> dict:
    flags = stopped_or_full(response.text or "")
    data = {}
    try:
        parsed = read_json(response)
        if isinstance(parsed, dict):
            data = parsed
    except TeamCallError:
        data = {}
    successes, errored = invite_emails(data, emails)
    return {
        "successes": successes,
        "errored": errored,
        "seatFull": flags["seatFull"],
        "stopped": flags["stopped"],
    }


def stopped_or_full(text: str) -> dict:
    lowered = text.lower()
    if "deactivated_workspace" in lowered or "workspace_not_found" in lowered:
        return {"stopped": True, "seatFull": False}
    if "seat_true_up_pending" in lowered or "true-up" in lowered or "true_up" in lowered:
        return {"stopped": False, "seatFull": True}
    return {"stopped": False, "seatFull": False}


def invite_known_stop(response):
    if is_html(response) or response.status_code >= 500 or response.status_code not in (401, 403):
        return None
    flags = stopped_or_full(response.text or "")
    if flags["seatFull"] or flags["stopped"]:
        return flags
    return None


def usage_from(data) -> dict:
    pct5h = pct7d = reset5h = reset7d = None
    limit_reached = None
    allowed = None
    for node in walk(data):
        if "limit_reached" in node and isinstance(node.get("limit_reached"), bool):
            limit_reached = node["limit_reached"]
        if "allowed" in node and isinstance(node.get("allowed"), bool):
            allowed = node["allowed"]
        pct = node.get("pct_5h", node.get("used_percent", node.get("usedPercent")))
        seconds = node.get("limit_window_seconds", node.get("window_seconds"))
        name = str(node.get("name") or node.get("id") or "")
        reset = node.get("reset_after_seconds", node.get("reset_after"))
        if node.get("pct_5h") is not None:
            pct5h = node.get("pct_5h")
        if node.get("pct_7d") is not None:
            pct7d = node.get("pct_7d")
        if node.get("reset_5h") is not None:
            reset5h = node.get("reset_5h")
        if node.get("reset_7d") is not None:
            reset7d = node.get("reset_7d")
        if isinstance(pct, (int, float)) and pct5h is None and (seconds in (18000, "18000") or "5h" in name):
            pct5h = pct
            reset5h = reset if isinstance(reset, (int, float)) else reset5h
        if isinstance(pct, (int, float)) and pct7d is None and (seconds in (604800, 2592000, "604800", "2592000") or "7d" in name or "30d" in name):
            pct7d = pct
            reset7d = reset if isinstance(reset, (int, float)) else reset7d
    status = "unprobed"
    if limit_reached is True or allowed is False or (isinstance(pct7d, (int, float)) and pct7d >= 100):
        status = "exhausted"
    elif isinstance(pct5h, (int, float)) and pct5h >= 100:
        status = "short_window"
    elif pct5h is not None or pct7d is not None:
        status = "probed"
    return {
        "pct5h": pct5h,
        "pct7d": pct7d,
        "reset5h": reset5h,
        "reset7d": reset7d,
        "limitReached": limit_reached,
        "allowed": allowed,
        "usageStatus": status,
    }


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


def team_snapshot(body: dict):
    session = body.get("session")
    if isinstance(session, str):
        session = json.loads(session)
    workspace_id = str(body.get("workspaceId") or "")
    if not isinstance(session, dict) or not workspace_id:
        return fail("BAD_INPUT", "缺少母号 session 或空间")
    http = open_session(body.get("proxy") or "")
    bind_device(http, body, session)
    precheck(http)
    exchanged = exchange_workspace(http, living_access(http, session, workspace_id), workspace_id)
    token = exchanged.get("accessToken") or exchanged.get("access_token")
    return ok(**snapshot(http, token, workspace_id))


def team_invite(body: dict):
    emails = [str(item).strip() for item in body.get("emails") or [] if str(item).strip()]
    if not emails or len(emails) > 25:
        return fail("BAD_INPUT", "一次最多邀请 25 个")
    session = body.get("session")
    if isinstance(session, str):
        session = json.loads(session)
    workspace_id = str(body.get("workspaceId") or "")
    http = open_session(body.get("proxy") or "")
    bind_device(http, body, session)
    precheck(http)
    exchanged = exchange_workspace(http, living_access(http, session, workspace_id), workspace_id)
    token = exchanged.get("accessToken") or exchanged.get("access_token")
    path = f"/backend-api/accounts/{workspace_id}/invites"
    payload = {
        "email_addresses": emails,
        "flow_id": str(uuid.uuid4()),
        "role": "standard-user",
        "seat_type": "default",
        "resend_emails": True,
        "submission_id": str(uuid.uuid4()),
    }
    headers = browser_headers(token, workspace_id, path, f"{CHATGPT}/admin/members?tab=members", http)
    response = request_with_retry(http, "POST", f"{CHATGPT}{path}", headers=headers, payload=payload)
    try:
        flags = invite_known_stop(response)
        if flags is None:
            response = classify(response, session_call=True)
        try:
            outcome = invite_outcome(response, emails)
        except TeamCallError:
            if flags is None:
                raise
            outcome = {"successes": [], "errored": emails, "seatFull": flags["seatFull"], "stopped": flags["stopped"]}
        if outcome.get("stopped"):
            outcome["message"] = "空间不可用已停止"
        elif outcome.get("seatFull"):
            outcome["message"] = "席位已满已停止"
        return ok(**outcome, inviteSent=True)
    except TeamCallError as error:
        error.invite_sent = True
        raise


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


def jwt_auth(token: str) -> dict:
    try:
        from vendor.lib.session_formats import b64url_decode_json
        payload = b64url_decode_json(token)
    except Exception:
        return {}
    auth = payload.get("https://api.openai.com/auth")
    return auth if isinstance(auth, dict) else {}


def jwt_account_id(token: str) -> str:
    return str(jwt_auth(token).get("chatgpt_account_id") or "")


def workspace_file(exchanged: dict, email: str) -> dict:
    from app.formats import session_to_payloads
    access = str(exchanged.get("accessToken") or exchanged.get("access_token") or "")
    if jwt_account_id(access) == "":
        raise TeamCallError("AUTH", "没有换到目标空间的 token")
    session = {
        "accessToken": access,
        "refreshToken": exchanged.get("refreshToken") or exchanged.get("refresh_token") or "",
        "idToken": exchanged.get("idToken") or exchanged.get("id_token") or "",
        "email": exchanged.get("email") or email,
    }
    built = session_to_payloads(session, email)
    item = built.get("item") or {}
    accounts = ((built.get("sub2api") or {}).get("accounts") or [])
    account = accounts[0] if accounts else {}
    return {
        "accessToken": item.get("access_token") or access,
        "refreshToken": item.get("refresh_token") or "",
        "idToken": item.get("id_token") or "",
        "accountId": item.get("account_id") or "",
        "userId": item.get("user_id") or "",
        "planType": item.get("plan_type") or "",
        "expiresAt": item.get("expires_at") or "",
        "raw": account,
    }


def close_http(http) -> None:
    closer = getattr(http, "close", None)
    if callable(closer):
        try:
            closer()
        except Exception:
            pass


def precheck_proxy(proxy: str) -> None:
    http = open_session(proxy)
    try:
        precheck(http)
    finally:
        close_http(http)


def http_has_cookies(http) -> bool:
    jar = getattr(http, "cookies", None)
    if jar is None:
        return False
    items = getattr(jar, "items", None)
    if isinstance(items, list):
        return any(item for item in items)
    if isinstance(jar, dict):
        return bool(jar)
    try:
        return bool(list(jar))
    except Exception:
        return False


def team_onboard(body: dict):
    email = str(body.get("email") or "").strip()
    password = str(body.get("password") or "")
    totp = str(body.get("totp") or "")
    workspace_id = str(body.get("workspaceId") or "")
    if not email or not password or not totp or not workspace_id:
        return fail("BAD_INPUT", "上车缺少邮箱、密码或 2FA")
    proxy = require_socks(body.get("proxy") or "")
    try:
        precheck_proxy(proxy)
        http, tokens = login_child(email, password, totp, proxy, workspace_id)
        personal = pkce_access(tokens)
        if not personal and not http_has_cookies(http):
            return fail("AUTH", "登录后没有拿到 ChatGPT session")
        join_failed = False
        for path in (
            f"/backend-api/accounts/{workspace_id}/invites/request",
            f"/backend-api/accounts/{workspace_id}/invites/accept",
        ):
            response = request_with_retry(
                http,
                "POST",
                f"{CHATGPT}{path}",
                headers=browser_headers(personal, workspace_id, path, f"{CHATGPT}/", http),
                payload={},
            )
            if is_html(response):
                return fail("EGRESS_BLOCKED", "出口被拦截，已停止")
            if response.status_code >= 400:
                join_failed = True
        check = "/backend-api/accounts/check/v4-2023-04-27"
        checked = request_with_retry(
            http,
            "GET",
            f"{CHATGPT}{check}?timezone_offset_min=-480",
            headers=browser_headers(personal, workspace_id, check, f"{CHATGPT}/", http),
        )
        if is_html(checked) or checked.status_code >= 400:
            return fail("AUTH", "加入空间失败")
        exchanged = exchange_workspace(http, personal, workspace_id)
        exchanged.setdefault("email", email)
        access = str(exchanged.get("accessToken") or exchanged.get("access_token") or "")
        if jwt_account_id(access) != workspace_id:
            return fail("AUTH", "加入空间失败" if join_failed else "没有换到目标空间的 token")
        return ok(**workspace_file(exchanged, email))
    except TeamCallError as error:
        return fail(error.code, error.message)
    except Exception as error:
        if type(error).__name__ != "ReauthError":
            raise
        return fail("AUTH", str(error) or "登录失败")


def team_usage(body: dict):
    token = str(body.get("accessToken") or "").strip()
    workspace_id = str(body.get("workspaceId") or "")
    if not token:
        return fail("AUTH", "没有可探测的 access token", usageStatus="auth_error")
    http = open_session(body.get("proxy") or "")
    precheck(http)
    headers = {
        "Authorization": f"Bearer {token}",
        "Originator": "codex_cli_rs",
        "User-Agent": "codex_cli_rs/0.146.0",
        "Version": "0.146.0",
        "Accept": "application/json",
    }
    if workspace_id:
        headers["chatgpt-account-id"] = workspace_id
    response = request_with_retry(http, "GET", f"{CHATGPT}/backend-api/wham/usage", headers=headers)
    if response.status_code == 429:
        return fail("RATE_LIMITED", "上游限流，请稍后再探测", 429, usageStatus="unprobed")
    if response.status_code in (401, 403):
        return fail("AUTH" if not is_html(response) else "EGRESS_BLOCKED", "登录或出口失败", usageStatus="auth_error")
    data = read_json(response)
    return ok(**usage_from(data))


def delete_member(http, token: str, workspace_id: str, user_id: str) -> int:
    path = f"/backend-api/accounts/{workspace_id}/users/{user_id}"
    response = request_with_retry(
        http,
        "DELETE",
        f"{CHATGPT}{path}",
        headers=browser_headers(token, workspace_id, path, f"{CHATGPT}/admin/members", http),
    )
    if is_html(response):
        raise TeamCallError("EGRESS_BLOCKED", "出口被拦截，已停止", response.status_code)
    return response.status_code


def pkce_access(tokens) -> str:
    if not isinstance(tokens, dict):
        return ""
    token = tokens.get("access_token") or tokens.get("accessToken") or ""
    return token.strip() if isinstance(token, str) else ""


def delete_with_login_cookies(http, workspace_id: str, user_id: str):
    if not user_id or not http_has_cookies(http):
        return None
    return delete_member(http, "", workspace_id, user_id)


def delete_after_login(http, tokens: dict, workspace_id: str, user_id: str):
    personal = pkce_access(tokens)
    if not personal:
        return delete_with_login_cookies(http, workspace_id, user_id)
    token = ""
    blocked = False
    try:
        exchanged = exchange_workspace(http, personal, workspace_id)
        token = str(exchanged.get("accessToken") or exchanged.get("access_token") or "")
        if jwt_account_id(token) != workspace_id:
            token = ""
    except TeamCallError as error:
        blocked = error.code == "EGRESS_BLOCKED"
        if blocked and jwt_account_id(personal) == workspace_id:
            token = personal
    if token:
        return delete_member(http, token, workspace_id, user_id)
    if blocked:
        return delete_with_login_cookies(http, workspace_id, user_id)
    return None


def mother_session(value):
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    return value if isinstance(value, dict) else None


def team_kick(body: dict):
    workspace_id = str(body.get("workspaceId") or "")
    user_id = str(body.get("userId") or "")
    if not workspace_id or not user_id:
        return fail("BAD_INPUT", "缺少要退出的成员")
    try:
        proxy = require_socks(body.get("proxy") or "")
        http = open_session(proxy)
        apply_saved_device(http, body, mother_session(body.get("session")))
        precheck(http)
        stored = str(body.get("accessToken") or "").strip()
        if stored:
            try:
                status = delete_member(http, stored, workspace_id, user_id)
            except TeamCallError as error:
                if error.code != "EGRESS_BLOCKED":
                    return fail(error.code, error.message)
                status = 403
            if status in (200, 204):
                return ok(temporary=True)
            if status not in (401, 403):
                return fail("UPSTREAM", f"退出失败：HTTP {status}")
        password = str(body.get("password") or "")
        totp = str(body.get("totp") or "")
        email = str(body.get("email") or "").strip()
        if password and totp and email:
            try:
                login_http, tokens = login_child(email, password, totp, proxy, workspace_id)
                status = delete_after_login(login_http, tokens, workspace_id, user_id)
                if status in (200, 204):
                    return ok(temporary=True)
                if status not in (None, 401, 403):
                    return fail("UPSTREAM", f"退出失败：HTTP {status}")
            except TeamCallError:
                pass
            except Exception as error:
                if type(error).__name__ != "ReauthError":
                    raise
        session = mother_session(body.get("session"))
        if session:
            bind_device(http, body, session)
            try:
                exchanged = exchange_workspace(http, living_access(http, session, workspace_id), workspace_id)
                token = str(exchanged.get("accessToken") or exchanged.get("access_token") or "")
                status = delete_member(http, token, workspace_id, user_id)
            except TeamCallError as error:
                return mother_kick_error(error)
            return mother_kick_status(status)
        return fail("AUTH", "自退失败，且没有母号会话可兜底")
    except TeamCallError as error:
        return fail(error.code, error.message)


def team_revoke(body: dict):
    email = str(body.get("email") or "").strip()
    workspace_id = str(body.get("workspaceId") or "")
    session = body.get("session")
    if isinstance(session, str):
        session = json.loads(session)
    if not email or not workspace_id or not isinstance(session, dict):
        return fail("BAD_INPUT", "缺少要撤回的邀请")
    http = open_session(body.get("proxy") or "")
    bind_device(http, body, session)
    precheck(http)
    exchanged = exchange_workspace(http, living_access(http, session, workspace_id), workspace_id)
    token = exchanged.get("accessToken") or exchanged.get("access_token")
    path = f"/backend-api/accounts/{workspace_id}/invites"
    headers = browser_headers(token, workspace_id, path, f"{CHATGPT}/admin/members", http)
    response = classify(
        request_with_retry(http, "DELETE", f"{CHATGPT}{path}", headers=headers, payload={"email_address": email}),
        session_call=True,
    )
    if response.status_code >= 400:
        return fail("UPSTREAM", "撤回邀请没有成功")
    return ok()


ROUTES = {
    "/internal/session/inspect": inspect_session,
    "/internal/team/snapshot": team_snapshot,
    "/internal/team/invite": team_invite,
    "/internal/team/onboard": team_onboard,
    "/internal/team/usage": team_usage,
    "/internal/team/kick": team_kick,
    "/internal/team/revoke": team_revoke,
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
        try:
            status, payload = ROUTES[path](body)
        except TeamCallError as error:
            status, payload = error_payload(error)
        except Exception as error:
            print(f"[gptcdk-protocol] {type(error).__name__} {path}", flush=True)
            status, payload = fail("UPSTREAM", "协议服务处理失败")
        http = getattr(_bound, "http", None)
        try:
            _bound.http = None
        except Exception:
            pass
        payload = attach_session_update(http, payload)
        self._send(status if status < 500 else 200, payload)


def main() -> None:
    if not TOKEN:
        print("[gptcdk-protocol] PROTOCOL_WORKER_TOKEN 未配置，Team 调用会拒绝", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
