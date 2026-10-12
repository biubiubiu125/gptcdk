"""账号提取：账密登录，5X Team 只收单个 Business 空间 token。"""

from __future__ import annotations

import re
from typing import Any, Callable

from team_http import TeamCallError, require_socks
from vendor.lib.session_formats import b64url_decode_json

BUSINESS_PLAN = "self_serve_business_prolite"
SELLER_TEAM_TAG = "5X Team"


class ExtractStop(Exception):
    def __init__(self, code: str, message: str, temporary: bool) -> None:
        super().__init__(message)
        self.code = code
        self.temporary = temporary


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    cleaned = str(text or "")
    for secret in secrets:
        if secret and len(str(secret)) >= 4:
            cleaned = cleaned.replace(str(secret), "***")
    cleaned = re.sub(r"socks5h?://\S+", "socks5://***", cleaned, flags=re.I)
    return cleaned[:180]


def password_rejected(status: int, mail_client: Any) -> bool:
    try:
        code = int(status or 0)
    except (TypeError, ValueError):
        code = 0
    return code == 401 and mail_client is None


def note_password_verify_failure(client: Any, status: int, mail_client: Any) -> bool:
    if not password_rejected(status, mail_client):
        return False
    client.last_oauth_error = "invalid_username_or_password"
    return True


def note_email_otp_without_mailbox(client: Any) -> None:
    client.last_oauth_error = "email_verification_required"


def jwt_claims(token: str) -> dict:
    try:
        data = b64url_decode_json(token)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def claim(payload: dict, key: str) -> str:
    direct = payload.get(key)
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    auth = payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        nested = auth.get(key)
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return ""


def normalize_account(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    nested = item.get("account") if isinstance(item.get("account"), dict) else {}
    source = {**item, **nested}
    account_id = str(source.get("id") or source.get("account_id") or "").strip()
    if not account_id:
        return None
    return {
        "id": account_id,
        "structure": str(source.get("structure") or "").strip(),
        "plan_type": str(source.get("plan_type") or source.get("planType") or "").strip(),
        "deactivated": bool(source.get("is_deactivated") or source.get("deactivated")),
    }


def iter_accounts(payload: Any):
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("accounts"), dict):
        items = list(payload["accounts"].values())
    elif isinstance(payload, dict) and isinstance(payload.get("accounts"), list):
        items = payload["accounts"]
    elif isinstance(payload, dict):
        items = [payload]
    else:
        items = []
    for item in items:
        normalized = normalize_account(item)
        if normalized:
            yield normalized


def select_business_workspace(payload: Any, forced_id: str | None = None) -> dict:
    rows = [
        row for row in iter_accounts(payload)
        if row["structure"] == "workspace"
        and row["plan_type"] == BUSINESS_PLAN
        and not row["deactivated"]
    ]
    forced = str(forced_id or "").strip()
    if forced:
        match = [row for row in rows if row["id"] == forced]
        if len(match) == 1:
            return {"ok": True, "workspace_id": match[0]["id"]}
        return fail("PLAN_MISMATCH", "空间核对失败", temporary=False)
    if not rows:
        return fail("WORKSPACE_MISSING", "没有可用的 5X Team 空间", temporary=False)
    if len(rows) > 1:
        return fail("WORKSPACE_AMBIGUOUS", "存在多个 5X Team 空间，已停止", temporary=False)
    return {"ok": True, "workspace_id": rows[0]["id"]}


def personal_plan_allowed(payload: dict) -> bool:
    plan = claim(payload, "chatgpt_plan_type")
    if not plan or plan in {"free", "team"} or plan.startswith("self_serve_business"):
        return False
    account_id = claim(payload, "chatgpt_account_id")
    workspace_id = claim(payload, "chatgpt_workspace_id") or claim(payload, "workspace_id")
    if account_id and workspace_id and account_id != workspace_id:
        return False
    return True


def fail(code: str, message: str, *, temporary: bool) -> dict:
    return {"ok": False, "temporary": temporary, "code": code, "message": redact(message)}


def classify_login_failure(code: str, message: str) -> dict:
    raw = str(code or "").strip()
    text = f"{raw} {message or ''}".lower()
    if "429" in text or "rate_limit" in text:
        return {"code": raw or "RETRY", "temporary": True}
    permanent = (
        "invalid_username_or_password",
        "mfa_totp_",
        "personal_token",
        "plan_mismatch",
        "workspace_missing",
        "workspace_ambiguous",
        "no_proxy",
        "密码错误",
        "密码不正确",
        "邮箱或密码",
        "用户名或密码",
        "2fa 动态码未通过",
        "手机号",
        "已停用",
        "已封禁",
        "deactivated",
    )
    if any(item in text for item in permanent):
        return {"code": raw or "FAILED", "temporary": False}
    return {"code": raw or "RETRY", "temporary": True}


def classified_exception(error: Exception, secrets: tuple[str, ...] = ()) -> dict:
    message = redact(str(error), secrets)
    kind = classify_login_failure(getattr(error, "code", ""), message)
    if isinstance(error, TeamCallError) and error.code == "NO_PROXY":
        kind = {"code": "NO_PROXY", "temporary": False}
    return {"ok": False, "temporary": kind["temporary"], "code": kind["code"], "message": message or kind["code"]}


def token_pair(data: dict) -> tuple[str, str, str]:
    if not isinstance(data, dict):
        return "", "", ""
    return (
        token_value(data, "access_token", "accessToken"),
        token_value(data, "refresh_token", "refreshToken"),
        token_value(data, "id_token", "idToken"),
    )


def workspace_token_ready(access: str, refresh: str, workspace_id: str) -> bool:
    if not access or not refresh:
        return False
    claims = jwt_claims(access)
    return claim(claims, "chatgpt_account_id") == workspace_id and claim(claims, "chatgpt_plan_type") == BUSINESS_PLAN


def exchange_or_mint(session, workspace_id: str, proxy: str, exchange: Callable, mint: Callable) -> dict:
    """空间交换拿不到 refresh 时，用已知空间号重新授权。不把个人 token 当成品交付。"""
    session_expired = False
    exchanged: dict = {}
    try:
        current = exchange(session, workspace_id, proxy)
        exchanged = current if isinstance(current, dict) else {}
    except TeamCallError as error:
        if error.code != "SESSION_EXPIRED":
            raise
        session_expired = True
    access, refresh, id_token = token_pair(exchanged)
    if workspace_token_ready(access, refresh, workspace_id):
        return {"access_token": access, "refresh_token": refresh, "id_token": id_token}
    minted_raw = mint(session, workspace_id, proxy)
    minted = minted_raw if isinstance(minted_raw, dict) else {}
    minted_access, minted_refresh, minted_id = token_pair(minted)
    if minted_access and minted_refresh:
        return {"access_token": minted_access, "refresh_token": minted_refresh, "id_token": minted_id}
    if access and refresh:
        return {"access_token": access, "refresh_token": refresh, "id_token": id_token}
    if session_expired:
        raise TeamCallError("SESSION_EXPIRED", "登录会话已失效，请重新登录")
    return {"access_token": "", "refresh_token": "", "id_token": ""}


def token_value(data: dict, *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def success(data: dict, claims: dict, workspace_id: str | None, email: str) -> dict:
    return {
        "ok": True,
        "temporary": False,
        "code": "OK",
        "message": "提取完成",
        "accessToken": token_value(data, "access_token", "accessToken"),
        "refreshToken": token_value(data, "refresh_token", "refreshToken"),
        "idToken": token_value(data, "id_token", "idToken"),
        "accountId": claim(claims, "chatgpt_account_id"),
        "userId": claim(claims, "user_id") or claim(claims, "chatgpt_user_id"),
        "planType": claim(claims, "chatgpt_plan_type"),
        "remoteWorkspaceId": workspace_id,
        "email": email,
    }


def run_extract(
    body: dict,
    login: Callable,
    list_accounts: Callable,
    exchange: Callable,
) -> dict:
    tag = str(body.get("subscriptionTag") or "").strip()
    proxy = str(body.get("proxy") or "").strip()
    email = str(body.get("email") or "").strip()
    password = str(body.get("password") or "")
    totp = str(body.get("totp") or "")
    forced = str(body.get("workspaceId") or "").strip() or None
    secrets = (password, totp, proxy)
    try:
        require_socks(proxy)
    except TeamCallError as error:
        return fail(error.code or "NO_PROXY", "没有可用的 SOCKS 代理", temporary=False)
    if not email or not password or not totp:
        return fail("BAD_INPUT", "账密不完整", temporary=False)
    try:
        session = login(email, password, totp, proxy)
        tokens = session.get("tokens") if isinstance(session, dict) else {}
        if not isinstance(tokens, dict):
            tokens = {}
        access = token_value(tokens, "access_token", "accessToken")
        refresh = token_value(tokens, "refresh_token", "refreshToken")
        if not access or not refresh:
            return fail("REFRESH_MISSING", "没有拿到 refresh_token", temporary=True)
        if tag == SELLER_TEAM_TAG:
            listing = list_accounts(session, proxy)
            selected = select_business_workspace(listing, forced)
            if not selected.get("ok"):
                return selected
            workspace_id = str(selected["workspace_id"])
            claims = jwt_claims(access)
            current = tokens
            if claim(claims, "chatgpt_account_id") != workspace_id or claim(claims, "chatgpt_plan_type") != BUSINESS_PLAN:
                current = exchange(session, workspace_id, proxy)
                if not isinstance(current, dict):
                    return fail("UPSTREAM", "没有换到目标空间的 token", temporary=True)
                access = token_value(current, "access_token", "accessToken")
                refresh = token_value(current, "refresh_token", "refreshToken")
                claims = jwt_claims(access)
            if not refresh:
                return fail("REFRESH_MISSING", "没有拿到 refresh_token", temporary=True)
            if claim(claims, "chatgpt_account_id") != workspace_id or claim(claims, "chatgpt_plan_type") != BUSINESS_PLAN:
                return fail("PLAN_MISMATCH", "空间核对失败", temporary=False)
            return success(current, claims, workspace_id, email)
        claims = jwt_claims(access)
        if not personal_plan_allowed(claims):
            return fail("PLAN_MISMATCH", "个人订阅核对失败", temporary=False)
        return success(tokens, claims, None, email)
    except Exception as error:
        return classified_exception(error, secrets)
