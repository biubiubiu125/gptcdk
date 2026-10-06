"""Team 出口和代理规则。不登录，也不打印请求内容。"""

from __future__ import annotations

BANNED_LOCS = {"HK", "CN", "RU", "KP", "IR", "SY", "CU"}


class TeamCallError(RuntimeError):
    def __init__(self, code: str, message: str, http_status: int = 0):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def require_socks(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise TeamCallError("NO_PROXY", "没有可用的 SOCKS 代理")
    lowered = text.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        raise TeamCallError("NO_PROXY", "只接受 SOCKS 代理")
    if lowered.startswith("socks5://") or lowered.startswith("socks5h://"):
        return text
    parts = text.split(":")
    if len(parts) == 4 and parts[1].isdigit() and parts[0] and parts[2] and parts[3]:
        from urllib.parse import quote
        return f"socks5://{quote(parts[2], safe='')}:{quote(parts[3], safe='')}@{parts[0]}:{parts[1]}"
    if len(parts) == 2 and parts[1].isdigit() and parts[0]:
        return f"socks5://{parts[0]}:{parts[1]}"
    raise TeamCallError("NO_PROXY", "SOCKS 代理格式应为 socks5:// 或 host:port:user:pass")


def location_from_trace(text: str) -> str:
    for line in str(text or "").splitlines():
        if line.startswith("loc="):
            return line.split("=", 1)[1].strip().upper()
    return ""


def assert_egress_allowed(trace_text: str) -> str:
    loc = location_from_trace(trace_text)
    if not loc:
        raise TeamCallError("EGRESS_BLOCKED", "出口预检失败，已停止")
    if loc in BANNED_LOCS:
        raise TeamCallError("BANNED_EGRESS", "出口在封禁地区，已停止")
    return loc
