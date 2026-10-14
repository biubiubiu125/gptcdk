"""找回登录的客户端断开标记。只拦后续请求，不把邮箱凭据带出进程。"""

from __future__ import annotations

import contextvars
import select
import socket
import threading
from typing import Any


class ExtractCancelled(Exception):
    def __init__(self) -> None:
        super().__init__("提取已中断")
        self.code = "ABORTED"
        self.temporary = True


class CancelState:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.sessions: list[Any] = []


_state: contextvars.ContextVar[CancelState | None] = contextvars.ContextVar("extract_cancel", default=None)


def install_cancel(state: CancelState):
    return _state.set(state)


def reset_cancel(token) -> None:
    _state.reset(token)


def cancelled() -> bool:
    state = _state.get()
    return bool(state and state.stop.is_set())


def raise_if_cancelled() -> None:
    if cancelled():
        raise ExtractCancelled()


def wrap_session(session: Any) -> Any:
    if session is None or getattr(session, "_gptcdk_cancel_wrapped", False):
        return session
    state = _state.get()
    if state is not None:
        state.sessions.append(session)
    for name in ("request", "get", "post", "put", "delete"):
        original = getattr(session, name, None)
        if not callable(original):
            continue

        def make(fn):
            def wrapped(*args, **kwargs):
                raise_if_cancelled()
                return fn(*args, **kwargs)

            return wrapped

        setattr(session, name, make(original))
    session._gptcdk_cancel_wrapped = True
    return session


def client_gone(handler: Any) -> bool:
    sock = getattr(handler, "connection", None)
    if sock is None:
        return False
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except Exception:
        return True
    if not readable:
        return False
    try:
        peeked = sock.recv(1, socket.MSG_PEEK)
    except BlockingIOError:
        return False
    except Exception:
        return True
    return peeked == b""


def watch_disconnect(handler: Any, state: CancelState, done: threading.Event) -> None:
    while not done.is_set() and not state.stop.is_set():
        if client_gone(handler):
            state.stop.set()
            for session in list(state.sessions):
                close = getattr(session, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass
            return
        done.wait(0.2)
