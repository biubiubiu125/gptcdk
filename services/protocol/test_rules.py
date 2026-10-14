import json
import unittest
from types import SimpleNamespace

from team_http import TeamCallError, assert_egress_allowed, location_from_trace, require_socks
import internal_server as worker


class RulesTest(unittest.TestCase):
    def test_socks_order_shapes(self):
        self.assertEqual(require_socks("socks5://127.0.0.1:1080"), "socks5://127.0.0.1:1080")
        self.assertTrue(require_socks("10.0.0.8:1080:user:pass").startswith("socks5://user:pass@10.0.0.8:1080"))
        with self.assertRaises(TeamCallError):
            require_socks("http://127.0.0.1:8080")
        with self.assertRaises(TeamCallError):
            require_socks("")

    def test_banned_region_stops(self):
        self.assertEqual(location_from_trace("fl=1\nloc=JP\n"), "JP")
        self.assertEqual(assert_egress_allowed("loc=JP"), "JP")
        with self.assertRaises(TeamCallError) as caught:
            assert_egress_allowed("loc=CN")
        self.assertEqual(caught.exception.code, "BANNED_EGRESS")
        with self.assertRaises(TeamCallError):
            assert_egress_allowed("")


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)
        self.headers = {"content-type": "text/html" if isinstance(payload, str) else "application/json"}

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("html")
        return self._payload


class TeamFlowTest(unittest.TestCase):
    def test_headers_stay_on_one_device_and_language(self):
        http = SimpleNamespace(headers={"Accept-Language": "en-US,en;q=0.9", "User-Agent": "TestAgent/1"}, oai_device_id="device-stable")
        first = worker.browser_headers("token", "ws", "/path", "https://chatgpt.com/", http)
        second = worker.browser_headers("token", "ws", "/path", "https://chatgpt.com/", http)
        self.assertEqual(first["oai-device-id"], "device-stable")
        self.assertEqual(second["oai-device-id"], first["oai-device-id"])
        self.assertEqual(first["oai-language"], "en-US")
        self.assertEqual(first["User-Agent"], "TestAgent/1")

    def test_empty_token_stays_up_and_rejects_calls(self):
        original_token = worker.TOKEN
        original_server = worker.ThreadingHTTPServer
        called = {}

        class FakeServer:
            def __init__(self, address, handler):
                called["address"] = address

            def serve_forever(self):
                called["served"] = True

        worker.TOKEN = ""
        worker.ThreadingHTTPServer = FakeServer
        try:
            worker.main()
        finally:
            worker.TOKEN = original_token
            worker.ThreadingHTTPServer = original_server
        self.assertTrue(called.get("served"))

    def test_empty_token_does_not_send_authorization(self):
        headers = worker.browser_headers("", "ws", "/path", "https://chatgpt.com/", object())
        self.assertNotIn("Authorization", headers)









    def test_authorize_url_uses_documented_scope_and_flags(self):
        stub_protocol_imports()
        from app.engine import build_authorize_url
        url = build_authorize_url("challenge", "state", "ws-team")
        self.assertIn("api.connectors.read", url)
        self.assertIn("api.connectors.invoke", url)
        self.assertIn("id_token_add_organizations=true", url)
        self.assertIn("codex_cli_simplified_flow=true", url)
        self.assertIn("originator=codex_cli_rs", url)
        self.assertIn("allowed_workspace_id=ws-team", url)
        self.assertIn("app_EMoamEEZ73f0CkXaXp7hrann", url)
        self.assertIn("localhost%3A1455", url)

    def test_token_exchange_sends_documented_originator(self):
        stub_protocol_imports()
        from vendor.lib.oauth_client import OAuthClient
        seen = {}

        class FakeSession:
            def post(self, url, **kwargs):
                seen["url"] = url
                seen["headers"] = kwargs.get("headers") or {}
                return FakeResponse(200, {"access_token": "at"})

        client = OAuthClient.__new__(OAuthClient)
        client.oauth_issuer = "https://auth.openai.com"
        client.oauth_redirect_uri = "http://localhost:1455/auth/callback"
        client.oauth_client_id = "app_EMoamEEZ73f0CkXaXp7hrann"
        client.session = FakeSession()
        client._log = lambda *args, **kwargs: None
        tokens = client._exchange_code_for_tokens("code", "verifier", "browser-ua", None)
        self.assertEqual(tokens["access_token"], "at")
        self.assertEqual(seen["headers"].get("originator"), "codex_cli_rs")
        self.assertEqual(seen["headers"].get("User-Agent"), "codex_cli_rs/0.146.0")
        self.assertNotIn("browser-ua", seen["headers"].get("User-Agent", ""))


    def test_documented_client_headers_are_forwarded_only_when_present(self):
        http = SimpleNamespace(headers={"Accept-Language": "en-US", "User-Agent": "ua", "oai-client-version": "1.2.3"}, oai_device_id="device-stable")
        headers = worker.browser_headers("token", "ws", "/path", "https://chatgpt.com/", http)
        self.assertEqual(headers.get("oai-client-version"), "1.2.3")
        self.assertNotIn("oai-client-build-number", headers)
        self.assertNotIn("oai-session-id", headers)
        self.assertNotIn("x-oai-is-client-observation", headers)
        self.assertNotIn("x-oai-is-pending-updates", headers)
        bare = worker.browser_headers("token", "ws", "/path", "https://chatgpt.com/", SimpleNamespace(headers={}, oai_device_id="d"))
        for name in ("oai-client-build-number", "oai-client-version", "oai-session-id", "x-oai-is-client-observation", "x-oai-is-pending-updates"):
            self.assertNotIn(name, bare)










    def test_authorize_releases_cookies_when_personal_token_is_blocked(self):
        stub_protocol_imports()
        import app.engine as engine
        from app.config import Settings
        from app.parsing import AccountLine

        jar = SimpleNamespace(items=[("__Secure-next-auth.session-token", "session-cookie")])
        client = SimpleNamespace(
            session=SimpleNamespace(cookies=jar, oai_device_id=""),
            device_id="dev",
            ua="ua",
            impersonate="chrome136",
            current_email="",
        )
        empty = SimpleNamespace(
            session=SimpleNamespace(cookies=SimpleNamespace(items=[]), oai_device_id=""),
            device_id="dev",
            ua="ua",
            impersonate="chrome136",
            current_email="",
        )

        class TokenFail:
            def __init__(self, *args, **kwargs):
                self.session = None

            def authorize_external_oauth_url(self, *args, **kwargs):
                return {"ok": True, "code": "auth-code", "state": kwargs.get("expected_state")}

            def _exchange_code_for_tokens(self, *args, **kwargs):
                return None

        class SessionBlocked:
            last_oauth_status = 403
            last_oauth_error = "final session fetch failed: [Session] HTTP 403"

            def __init__(self, *args, **kwargs):
                self.session = None

            def _oauth_complete_totp_mfa_for_continue(self, *args, **kwargs):
                return "https://auth.openai.com/next"

            def authorize_external_oauth_url(self, *args, **kwargs):
                self._oauth_complete_totp_mfa_for_continue()
                return {"ok": False, "error": self.last_oauth_error}

            def _exchange_code_for_tokens(self, *args, **kwargs):
                raise AssertionError("个人 token 被拦住时不能继续换 token")

        class PasswordFail:
            def __init__(self, *args, **kwargs):
                self.session = None
                self.last_oauth_status = 401
                self.last_oauth_error = "invalid_username_or_password"

            def _oauth_complete_totp_mfa_for_continue(self, *args, **kwargs):
                return ""

            def authorize_external_oauth_url(self, *args, **kwargs):
                self._oauth_complete_totp_mfa_for_continue()
                return {"ok": False, "error": self.last_oauth_error}

        originals = (engine.ChatGPTClient, engine.OAuthClient)
        settings = Settings(data_dir=engine.Path("."))
        account = AccountLine("kid@example.com", "chatgpt-pass", "JBSWY3DPEHPK3PXP", "")
        try:
            engine.ChatGPTClient = lambda **kwargs: client
            engine.OAuthClient = TokenFail
            returned, tokens = engine.open_login_session(
                account.email, account.password, account.totp_secret, "socks5://127.0.0.1:1080",
            )
            self.assertIs(returned, client)
            self.assertEqual(tokens, {})

            engine.ChatGPTClient = lambda **kwargs: empty
            with self.assertRaises(engine.ReauthError):
                engine.open_login_session(
                    account.email, account.password, account.totp_secret, "socks5://127.0.0.1:1080",
                )

            engine.ChatGPTClient = lambda **kwargs: client
            engine.OAuthClient = SessionBlocked
            returned, tokens = engine.open_login_session(
                account.email, account.password, account.totp_secret, "socks5://127.0.0.1:1080",
            )
            self.assertIs(returned, client)
            self.assertEqual(tokens, {})

            engine.OAuthClient = PasswordFail
            with self.assertRaises(engine.ReauthError):
                engine.open_login_session(
                    account.email, account.password, account.totp_secret, "socks5://127.0.0.1:1080",
                )
        finally:
            engine.ChatGPTClient, engine.OAuthClient = originals



    def test_handler_logs_exception_class_without_body(self):
        import io
        from contextlib import redirect_stdout

        original_route = worker.ROUTES["/internal/session/inspect"]
        original_token = worker.TOKEN

        def boom(_body):
            raise RuntimeError("secret-body-token")

        worker.ROUTES["/internal/session/inspect"] = boom
        worker.TOKEN = "team-token"
        sent = {}
        handler = worker.Handler.__new__(worker.Handler)
        handler.path = "/internal/session/inspect"
        handler.headers = {"Authorization": "Bearer team-token", "Content-Length": "40"}
        handler.rfile = io.BytesIO(b'{"accessToken":"secret-body-token"}')
        handler._send = lambda status, payload: sent.update(status=status, payload=payload)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                handler.do_POST()
        finally:
            worker.ROUTES["/internal/session/inspect"] = original_route
            worker.TOKEN = original_token
        self.assertEqual(sent["payload"]["message"], "协议服务处理失败")
        log = buf.getvalue()
        self.assertIn("RuntimeError", log)
        self.assertIn("/internal/session/inspect", log)
        self.assertNotIn("secret-body-token", log)

    def test_cookie_replay_json_401_is_session_expired_not_egress(self):
        response = FakeResponse(401, {"error": "unauthorized"})
        response.headers["set-cookie"] = "__Secure-next-auth.session-token=from-401; Path=/; HttpOnly"
        http = SimpleNamespace(oai_device_id="dev", headers={}, cookies=SimpleNamespace(set=lambda *args, **kwargs: None))
        original = worker.request_with_retry
        worker.request_with_retry = lambda *args, **kwargs: response
        try:
            with self.assertRaises(TeamCallError) as caught:
                worker.session_payload(http, "", "ws")
            self.assertEqual(caught.exception.code, "SESSION_EXPIRED")
            update = worker.session_update_from(http)
            self.assertEqual(update.get("sessionToken"), "from-401")
        finally:
            worker.request_with_retry = original

    def test_empty_401_cookie_is_not_a_rotation(self):
        response = FakeResponse(401, {"error": "unauthorized"})
        response.headers["set-cookie"] = "__Secure-next-auth.session-token=; Max-Age=0; Path=/"
        http = SimpleNamespace(oai_device_id="dev", headers={}, cookies=SimpleNamespace(set=lambda *args, **kwargs: None))
        original = worker.request_with_retry
        worker.request_with_retry = lambda *args, **kwargs: response
        try:
            with self.assertRaises(TeamCallError):
                worker.session_payload(http, "", "ws")
            update = worker.session_update_from(http) or {}
            self.assertNotIn("sessionToken", update)
            self.assertFalse(update.get("cookies"))
        finally:
            worker.request_with_retry = original

    def test_later_non_session_cookie_keeps_earlier_session_cookie(self):
        http = SimpleNamespace(oai_device_id="dev-1", headers={}, cookies=SimpleNamespace(set=lambda *args, **kwargs: None))
        first = FakeResponse(200, {"accessToken": "personal-at", "sessionToken": "rotated-session"})
        first.headers["set-cookie"] = "__Secure-next-auth.session-token=rotated-session; Path=/; HttpOnly"
        worker.remember_refresh(http, {"accessToken": "personal-at", "sessionToken": "rotated-session"}, first)
        second = FakeResponse(200, {"accessToken": "workspace-at"})
        second.headers["set-cookie"] = "__cf_bm=bm-1; Path=/; HttpOnly"
        worker.remember_refresh(http, {"accessToken": "workspace-at"}, second, keep_access=False)
        update = worker.session_update_from(http)
        names = {item["name"]: item["value"] for item in update.get("cookies") or []}
        self.assertEqual(names.get("__Secure-next-auth.session-token"), "rotated-session")
        self.assertEqual(names.get("__cf_bm"), "bm-1")
        self.assertEqual(update.get("sessionToken"), "rotated-session")
        self.assertEqual(update.get("accessToken"), "personal-at")

    def test_replay_replaces_stale_session_cookie_with_session_token(self):
        seen = {}
        http = SimpleNamespace(cookies=SimpleNamespace(set=lambda name, value, domain=None: seen.__setitem__(name, value)))
        worker.attach_living_session(http, {
            "sessionToken": "newer-session",
            "cookies": [{"name": "__Secure-next-auth.session-token", "value": "stale-session", "domain": ".chatgpt.com"}],
        })
        self.assertEqual(seen.get("__Secure-next-auth.session-token"), "newer-session")


    def test_cookie_replay_html_401_stays_egress(self):
        original = worker.request_with_retry
        worker.request_with_retry = lambda *args, **kwargs: FakeResponse(401, "<html>blocked</html>")
        try:
            with self.assertRaises(TeamCallError) as caught:
                worker.session_payload(SimpleNamespace(oai_device_id="dev", headers={}), "", "ws")
            self.assertEqual(caught.exception.code, "EGRESS_BLOCKED")
        finally:
            worker.request_with_retry = original

    def test_same_device_id_is_reused(self):
        http = SimpleNamespace(oai_device_id="old", headers={})
        worker.bind_device(http, {"deviceId": "device-1"}, {})
        first = worker.browser_headers("token", "ws", "/api/auth/session", "https://chatgpt.com/", http)
        second = worker.browser_headers("token", "ws", "/backend-api/me", "https://chatgpt.com/", http)
        self.assertEqual(first["oai-device-id"], "device-1")
        self.assertEqual(second["oai-device-id"], "device-1")

    def test_session_replay_keeps_rotated_cookie(self):
        response = FakeResponse(200, {"accessToken": "fresh-at"})
        response.headers["set-cookie"] = "__Secure-next-auth.session-token=rotated-session; Path=/; HttpOnly"
        http = SimpleNamespace(oai_device_id="dev-1", headers={}, cookies=SimpleNamespace(set=lambda *args, **kwargs: None))
        worker.remember_refresh(http, response.json(), response)
        update = worker.session_update_from(http)
        self.assertEqual(update["accessToken"], "fresh-at")
        self.assertEqual(update["sessionToken"], "rotated-session")
        self.assertEqual(update["deviceId"], "dev-1")
        self.assertTrue(any(item["name"] == "__Secure-next-auth.session-token" and item["value"] == "rotated-session" for item in update["cookies"]))


def stub_protocol_imports():
    import sys
    import types
    if "requests" in sys.modules and hasattr(sys.modules["requests"], "__file__"):
        return
    requests = types.ModuleType("requests")
    adapters = types.ModuleType("requests.adapters")

    class HTTPAdapter:
        def __init__(self, *args, **kwargs):
            pass

    adapters.HTTPAdapter = HTTPAdapter
    requests.adapters = adapters
    urllib3 = types.ModuleType("urllib3")
    util = types.ModuleType("urllib3.util")
    retry = types.ModuleType("urllib3.util.retry")

    class Retry:
        def __init__(self, *args, **kwargs):
            pass

    retry.Retry = Retry
    sys.modules["requests"] = requests
    sys.modules["requests.adapters"] = adapters
    sys.modules["urllib3"] = urllib3
    sys.modules["urllib3.util"] = util
    sys.modules["urllib3.util.retry"] = retry


def jwt_with_account(account_id, user_id, plan):
    import base64
    payload = {
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id,
            "chatgpt_plan_type": plan,
        },
        "exp": 2000000000,
    }
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"h.{raw}.s"


class WritebackFixTest(unittest.TestCase):
    def test_post_returns_cookie_rotated_by_bound_mother(self):
        import io

        original_route = worker.ROUTES["/internal/session/inspect"]
        original_token = worker.TOKEN
        worker.TOKEN = "team-token"
        worker._bound.http = None

        def route(_body):
            http = SimpleNamespace(
                oai_device_id="",
                headers={},
                cookies=SimpleNamespace(set=lambda *args, **kwargs: None),
            )
            worker.bind_device(http, {"deviceId": "device-kept"}, {})
            response = FakeResponse(200, {"accessToken": "fresh-at"})
            response.headers["set-cookie"] = "__Secure-next-auth.session-token=rotated-session; Path=/; HttpOnly"
            worker.remember_refresh(http, response.json(), response)
            return 200, {"ok": True, "complete": True, "members": []}

        worker.ROUTES["/internal/session/inspect"] = route
        sent = {}
        handler = worker.Handler.__new__(worker.Handler)
        handler.path = "/internal/session/inspect"
        body = b'{"workspaceId":"ws-1"}'
        handler.headers = {"Authorization": "Bearer team-token", "Content-Length": str(len(body))}
        handler.rfile = io.BytesIO(body)
        handler._send = lambda status, payload: sent.update(status=status, payload=payload)
        try:
            handler.do_POST()
        finally:
            worker.ROUTES["/internal/session/inspect"] = original_route
            worker.TOKEN = original_token
            worker._bound.http = None
        update = (sent.get("payload") or {}).get("sessionUpdate") or {}
        self.assertEqual(update.get("sessionToken"), "rotated-session")
        self.assertEqual(update.get("accessToken"), "fresh-at")
        self.assertIsNone(getattr(worker._bound, "http", None))


    def test_cookie_items_keeps_every_set_cookie(self):
        class MultiHeaders:
            def get_list(self, name):
                if str(name).lower() == "set-cookie":
                    return [
                        "__Secure-next-auth.session-token=rotated; Path=/",
                        "oai-did=device-cookie; Path=/",
                    ]
                return []

            def get(self, name, default=None):
                if str(name).lower() == "set-cookie":
                    return "__Secure-next-auth.session-token=rotated; Path=/"
                return default

        class RawOnly:
            def get(self, name, default=None):
                if str(name).lower() == "set-cookie":
                    return "__Secure-next-auth.session-token=first; Path=/"
                return default

        class RawHeaders:
            def getlist(self, name):
                if str(name).lower() == "set-cookie":
                    return [
                        "__Secure-next-auth.session-token=first; Path=/",
                        "__Host-next-auth.csrf-token=second; Path=/",
                    ]
                return []

        listed = worker.cookie_items(SimpleNamespace(headers=MultiHeaders()))
        self.assertEqual([item["name"] for item in listed], ["__Secure-next-auth.session-token", "oai-did"])
        raw = worker.cookie_items(SimpleNamespace(headers=RawOnly(), raw=SimpleNamespace(headers=RawHeaders())))
        self.assertEqual([item["name"] for item in raw], ["__Secure-next-auth.session-token", "__Host-next-auth.csrf-token"])



class ExtractFlowTest(unittest.TestCase):
    def token(self, payload):
        import base64
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"e30.{body}.sig"

    def test_plus_does_not_list_or_exchange(self):
        from app.extract import run_extract
        calls = {"list": 0, "exchange": 0}

        def login(email, password, totp, proxy):
            return {"tokens": {"access_token": self.token({"chatgpt_plan_type": "plus"}), "refresh_token": "rt"}}

        def list_accounts(session, proxy):
            calls["list"] += 1
            return {}

        def exchange(session, workspace_id, proxy):
            calls["exchange"] += 1
            return {}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "Plus",
        }, login, list_accounts, exchange)
        self.assertTrue(result["ok"])
        self.assertEqual(calls, {"list": 0, "exchange": 0})
        self.assertNotIn("password", result)
        self.assertNotIn("proxy", result)

    def test_two_business_workspaces_stop(self):
        from app.extract import run_extract

        def login(email, password, totp, proxy):
            return {"tokens": {"access_token": self.token({"chatgpt_plan_type": "plus"}), "refresh_token": "rt"}}

        def list_accounts(session, proxy):
            return {"accounts": {
                "a": {"id": "ws-1", "structure": "workspace", "plan_type": "self_serve_business_prolite"},
                "b": {"id": "ws-2", "structure": "workspace", "plan_type": "self_serve_business_prolite"},
            }}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "5X Team",
        }, login, list_accounts, lambda *args: {})
        self.assertFalse(result["ok"])
        self.assertFalse(result["temporary"])
        self.assertEqual(result["code"], "WORKSPACE_AMBIGUOUS")

    def test_missing_plan_is_not_saved(self):
        from app.extract import run_extract

        def login(email, password, totp, proxy):
            return {"tokens": {"access_token": self.token({"chatgpt_account_id": "personal"}), "refresh_token": "rt"}}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "Plus",
        }, login, lambda *args: (_ for _ in ()).throw(AssertionError("personal extract must not list workspaces")), lambda *args: {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "PLAN_MISMATCH")
        self.assertNotIn("access_token", result)

    def test_reclaim_missing_plan_keeps_tokens(self):
        from app.extract import run_extract

        def login(email, password, totp, proxy):
            return {"tokens": {"access_token": self.token({"email": email}), "refresh_token": "kept-refresh"}}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "Plus",
            "otpPolicy": "reclaim",
        }, login, lambda *args: (_ for _ in ()).throw(AssertionError("reclaim must not list workspaces")), lambda *args: {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["refreshToken"], "kept-refresh")
        self.assertTrue(result["accessToken"])

    def test_reclaim_explicit_bad_plan_still_drops_tokens(self):
        from app.extract import run_extract

        def run(plan):
            def login(email, password, totp, proxy):
                return {"tokens": {"access_token": self.token({"chatgpt_plan_type": plan, "email": email}), "refresh_token": "dropped"}}

            return run_extract({
                "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
                "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "Plus",
                "otpPolicy": "reclaim",
            }, login, lambda *args: {}, lambda *args: {})

        for plan in ("free", "team", "self_serve_business_prolite"):
            result = run(plan)
            self.assertFalse(result["ok"], plan)
            self.assertEqual(result["code"], "PLAN_MISMATCH", plan)
            self.assertNotIn("accessToken", result, plan)
            self.assertNotIn("refreshToken", result, plan)

    def test_reclaim_missing_plan_rejects_workspace_conflict(self):
        from app.extract import run_extract

        def login(email, password, totp, proxy):
            return {"tokens": {
                "access_token": self.token({"chatgpt_account_id": "personal", "chatgpt_workspace_id": "other"}),
                "refresh_token": "dropped",
            }}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "Plus",
            "otpPolicy": "reclaim",
        }, login, lambda *args: {}, lambda *args: {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "PLAN_MISMATCH")
        self.assertNotIn("accessToken", result)

    def test_mailbox_callback_waits_longer_than_reclaim_pickup(self):
        import app.mailbox_callback as callback

        seen = []

        def fake_urlopen(request, timeout=0):
            seen.append(timeout)
            raise TimeoutError("stop")

        original = callback.urllib.request.urlopen
        callback.urllib.request.urlopen = fake_urlopen
        try:
            box = callback.NestMailbox(1, "a@b.c", "http://nest", "token")
            self.assertIsNone(box._post_ids())
            self.assertIsNone(box._post(set()))
        finally:
            callback.urllib.request.urlopen = original
        self.assertEqual(len(seen), 2)
        self.assertGreaterEqual(min(seen), 45)

    def test_totp_rate_limit_is_temporary_and_wrong_code_is_not(self):
        from app.extract import classify_login_failure

        limited = classify_login_failure("mfa_totp_rejected_429", "授权失败：mfa_totp_rejected_429")
        wrong = classify_login_failure("mfa_totp_code_unavailable", "授权失败：mfa_totp_code_unavailable")
        self.assertTrue(limited["temporary"])
        self.assertFalse(wrong["temporary"])

    def test_exchange_mints_workspace_token_and_does_not_keep_personal(self):
        from app.extract import exchange_or_mint, jwt_claims

        personal = {"access_token": self.token({"chatgpt_plan_type": "plus", "chatgpt_account_id": "personal"}), "refresh_token": ""}
        minted = {
            "access_token": self.token({"chatgpt_plan_type": "self_serve_business_prolite", "chatgpt_account_id": "ws-team"}),
            "refresh_token": "minted-refresh",
            "id_token": "minted-id",
        }
        calls = []

        def exchange(session, workspace_id, proxy):
            calls.append(("exchange", workspace_id))
            return personal

        def mint(session, workspace_id, proxy):
            calls.append(("mint", workspace_id, session.get("password")))
            return minted

        result = exchange_or_mint(
            {"email": "a@b.c", "password": "secret-pass", "totp": "JBSWY3DPEHPK3PXP"},
            "ws-team",
            "socks5://127.0.0.1:1080",
            exchange,
            mint,
        )
        self.assertEqual(result["refresh_token"], "minted-refresh")
        self.assertNotIn("password", result)
        self.assertEqual(calls, [("exchange", "ws-team"), ("mint", "ws-team", "secret-pass")])
        self.assertEqual(jwt_claims(result["access_token"])["chatgpt_account_id"], "ws-team")

    def test_expired_session_mints_without_parent_copy(self):
        from app.extract import exchange_or_mint
        from team_http import TeamCallError

        minted = {
            "access_token": self.token({"chatgpt_plan_type": "self_serve_business_prolite", "chatgpt_account_id": "ws-team"}),
            "refresh_token": "minted-refresh",
        }

        def exchange(session, workspace_id, proxy):
            raise TeamCallError("SESSION_EXPIRED", "母号 session 已失效")

        result = exchange_or_mint({}, "ws-team", "socks5://127.0.0.1:1080", exchange, lambda *args: minted)
        self.assertEqual(result["refresh_token"], "minted-refresh")
        with self.assertRaises(TeamCallError) as raised:
            exchange_or_mint({}, "ws-team", "socks5://127.0.0.1:1080", exchange, lambda *args: {})
        self.assertEqual(raised.exception.code, "SESSION_EXPIRED")
        self.assertIn("登录会话已失效", str(raised.exception))
        self.assertNotIn("母号", str(raised.exception))

    def test_real_exchange_mints_with_known_workspace(self):
        import sys

        calls = {}

        def exchange_workspace(http, token, workspace_id):
            calls["exchange"] = workspace_id
            return {"accessToken": self.token({"chatgpt_plan_type": "plus", "chatgpt_account_id": "personal"})}

        def authorize_account(account, settings, workspace_id="", **kwargs):
            calls["mint"] = workspace_id
            calls["password"] = account.password
            return SimpleNamespace(session=SimpleNamespace()), {
                "access_token": self.token({"chatgpt_plan_type": "self_serve_business_prolite", "chatgpt_account_id": workspace_id}),
                "refresh_token": "minted-refresh",
            }

        original_exchange = worker.exchange_workspace
        original_engine = sys.modules.get("app.engine")
        worker.exchange_workspace = exchange_workspace
        sys.modules["app.engine"] = SimpleNamespace(authorize_account=authorize_account)
        try:
            result = worker.real_exchange({
                "client": SimpleNamespace(session=object()),
                "tokens": {"access_token": "personal-access"},
                "email": "a@b.c",
                "password": "secret-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "proxy": "socks5://127.0.0.1:1080",
            }, "ws-team", "socks5://127.0.0.1:1080")
        finally:
            worker.exchange_workspace = original_exchange
            if original_engine is None:
                sys.modules.pop("app.engine", None)
            else:
                sys.modules["app.engine"] = original_engine
        self.assertEqual(calls.get("mint"), "ws-team")
        self.assertEqual(result.get("refresh_token"), "minted-refresh")
        self.assertNotIn("password", result)
        self.assertNotIn("secret-pass", json.dumps(result))

    def test_personal_token_is_not_saved_for_team_tag(self):
        from app.extract import run_extract
        exchanged = {"called": 0}

        def login(email, password, totp, proxy):
            return {"tokens": {"access_token": self.token({"chatgpt_account_id": "personal", "chatgpt_plan_type": "plus"}), "refresh_token": "rt"}}

        def list_accounts(session, proxy):
            return {"accounts": {"a": {"id": "ws-1", "structure": "workspace", "plan_type": "self_serve_business_prolite"}}}

        def exchange(session, workspace_id, proxy):
            exchanged["called"] += 1
            return {"access_token": self.token({"chatgpt_account_id": "personal", "chatgpt_plan_type": "plus"}), "refresh_token": "rt2"}

        result = run_extract({
            "email": "a@b.c", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
            "proxy": "socks5://127.0.0.1:1080", "subscriptionTag": "5X Team",
        }, login, list_accounts, exchange)
        self.assertEqual(exchanged["called"], 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "PLAN_MISMATCH")
        self.assertNotIn("access_token", result)

    def test_password_401_without_mailbox_is_classified(self):
        from app.extract import note_password_verify_failure, note_email_otp_without_mailbox
        client = SimpleNamespace(last_oauth_error="")
        self.assertTrue(note_password_verify_failure(client, 401, None))
        self.assertEqual(client.last_oauth_error, "invalid_username_or_password")
        self.assertFalse(note_password_verify_failure(client, 401, object()))
        note_email_otp_without_mailbox(client)
        self.assertEqual(client.last_oauth_error, "email_verification_required")
        with open("vendor/lib/oauth_client.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertGreaterEqual(source.count("note_password_verify_failure"), 2)
        self.assertGreaterEqual(source.count("note_email_otp_without_mailbox"), 2)

    def test_extract_route_strips_secrets_and_does_not_bind_session(self):
        from app.extract import run_extract
        original = worker.run_extract if hasattr(worker, "run_extract") else None
        self.assertIn("/internal/account/extract", worker.ROUTES)
        status, payload = worker.account_extract({"email": "a@b.c"})
        self.assertEqual(status, 200)
        self.assertNotIn("password", payload)
        self.assertNotIn("sessionUpdate", payload)
        self.assertIsNone(getattr(worker._bound, "http", None))


    def test_reclaim_bare_401_is_not_password_failure(self):
        from app.extract import note_reclaim_bare_401, password_rejected, set_otp_policy, reset_otp_policy
        client = SimpleNamespace(last_oauth_error="")
        token = set_otp_policy("reclaim")
        try:
            self.assertTrue(note_reclaim_bare_401(client, 401, None))
            self.assertEqual(client.last_oauth_error, "email_verification_required")
            self.assertFalse(password_rejected(401, None))
        finally:
            reset_otp_policy(token)
        self.assertTrue(password_rejected(401, None))

    def test_mailbox_callback_drops_secret_fields(self):
        from app.mailbox_callback import NestMailbox
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                seen["body"] = self.rfile.read(length).decode("utf-8")
                seen["auth"] = self.headers.get("Authorization")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"id":"m1","code":"123456","refreshToken":"secret"}')

            def log_message(self, fmt, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            mailbox = NestMailbox(9, "a@b.c", f"http://127.0.0.1:{port}", "token")
            self.assertEqual(mailbox.wait_for_verification_code("a@b.c", timeout=1), "")
            self.assertNotIn("password", seen["body"])
            self.assertNotIn("clientId", seen["body"])
            self.assertEqual(seen["auth"], "Bearer token")
        finally:
            server.shutdown()
            server.server_close()

    def test_client_gone_stops_wrapped_request(self):
        import socket
        from app.cancel import CancelState, install_cancel, wrap_session, client_gone, reset_cancel, ExtractCancelled

        left, right = socket.socketpair()
        left.close()
        self.assertTrue(client_gone(SimpleNamespace(connection=right)))
        right.close()

        class Boom(Exception):
            pass

        class Session:
            def request(self, *args, **kwargs):
                raise Boom("should not run")

        state = CancelState()
        token = install_cancel(state)
        state.stop.set()
        session = wrap_session(Session())
        try:
            with self.assertRaises(ExtractCancelled):
                session.request("GET", "https://example.invalid")
        finally:
            reset_cancel(token)

    def test_account_extract_keeps_tokens_after_disconnect(self):
        import internal_server
        from app.cancel import CancelState, install_cancel, reset_cancel
        from app import extract

        def fake_run(body, login, list_workspaces, exchange):
            return {
                "ok": True,
                "accessToken": "kept-access",
                "refreshToken": "kept-refresh",
                "password": "secret",
            }

        original = extract.run_extract
        extract.run_extract = fake_run
        state = CancelState()
        state.stop.set()
        token = install_cancel(state)
        try:
            status, payload = internal_server.account_extract({"email": "a@b.c", "password": "x", "totp": "y"})
        finally:
            reset_cancel(token)
            extract.run_extract = original
        self.assertEqual(status, 200)
        self.assertEqual(payload.get("accessToken"), "kept-access")
        self.assertEqual(payload.get("refreshToken"), "kept-refresh")
        self.assertNotIn("password", payload)

    def test_mailbox_baseline_excludes_existing_ids(self):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from app.mailbox_callback import NestMailbox

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if body.get("baseline"):
                    self.wfile.write(b'{"ok":true,"ids":["old-mail"]}')
                    return
                excluded = set(body.get("excludeIds") or [])
                if "old-mail" in excluded:
                    self.wfile.write(b'{"ok":true,"id":"new-mail","code":"654321"}')
                else:
                    self.wfile.write(b'{"ok":true,"id":"old-mail","code":"111111"}')

            def log_message(self, fmt, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            mailbox = NestMailbox(9, "a@b.c", f"http://127.0.0.1:{port}", "token")
            ids = mailbox.snapshot_openai_message_ids("a@b.c")
            self.assertIn("old-mail", ids)
            self.assertEqual(mailbox.capture_openai_baseline("a@b.c", quiet=False), ids)
            self.assertEqual(mailbox.wait_for_verification_code("a@b.c", timeout=2), "654321")
        finally:
            server.shutdown()
            server.server_close()

    def test_reclaim_mailbox_401_cools_down_after_otp_exhausted(self):
        from app.extract import note_reclaim_password_exhausted, set_otp_policy, reset_otp_policy
        client = SimpleNamespace(last_oauth_error="")
        token = set_otp_policy("reclaim")
        try:
            note_reclaim_password_exhausted(client, 401, object())
            self.assertEqual(client.last_oauth_error, "invalid_username_or_password")
            client.last_oauth_error = "email_otp_rejected_401"
            note_reclaim_password_exhausted(client, 401, object())
            self.assertEqual(client.last_oauth_error, "email_otp_rejected_401")
            client.last_oauth_error = ""
            note_reclaim_password_exhausted(client, 409, object())
            self.assertEqual(client.last_oauth_error, "")
            note_reclaim_password_exhausted(client, 401, None)
            self.assertEqual(client.last_oauth_error, "")
        finally:
            reset_otp_policy(token)
        fresh = SimpleNamespace(last_oauth_error="")
        note_reclaim_password_exhausted(fresh, 401, object())
        self.assertEqual(fresh.last_oauth_error, "")
        with open("vendor/lib/oauth_client.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertGreaterEqual(source.count("note_reclaim_password_exhausted"), 2)

    def test_reclaim_mint_keeps_mailbox_client(self):
        import os
        import sys
        from app import mailbox_callback

        captured = []

        class FakeMailbox:
            def __init__(self, account_id, email, base, token):
                self.account_id = account_id

        def fake_authorize(account, settings, workspace_id="", mail_client=None, **kwargs):
            captured.append(mail_client)
            return object(), {"access_token": "mint-access", "refresh_token": "mint-refresh"}

        original_engine = sys.modules.get("app.engine")
        original_mailbox = mailbox_callback.NestMailbox
        original_token = worker.TOKEN
        original_url = os.environ.get("PROTOCOL_MAILBOX_URL")
        sys.modules["app.engine"] = SimpleNamespace(authorize_account=fake_authorize)
        mailbox_callback.NestMailbox = FakeMailbox
        worker.TOKEN = "worker-token"
        os.environ["PROTOCOL_MAILBOX_URL"] = "http://server:3000"
        try:
            session = worker.real_login(
                "a@b.c", "pw", "JBSWY3DPEHPK3PXP", "socks5://127.0.0.1:1080", 9,
            )
            self.assertIsInstance(session.get("mail_client"), FakeMailbox)
            tokens = worker.mint_workspace_oauth(session, "ws-1", "socks5://127.0.0.1:1080")
        finally:
            mailbox_callback.NestMailbox = original_mailbox
            worker.TOKEN = original_token
            if original_engine is None:
                sys.modules.pop("app.engine", None)
            else:
                sys.modules["app.engine"] = original_engine
            if original_url is None:
                os.environ.pop("PROTOCOL_MAILBOX_URL", None)
            else:
                os.environ["PROTOCOL_MAILBOX_URL"] = original_url
        self.assertEqual(len(captured), 2)
        self.assertIs(captured[1], session["mail_client"])
        self.assertEqual(tokens.get("refresh_token"), "mint-refresh")
        self.assertNotIn("mail_client", tokens)

    def test_reclaim_otp_failure_does_not_follow_continue_url(self):
        from app.extract import (
            note_reclaim_otp_exhausted,
            reclaim_follow_after_otp,
            reset_otp_policy,
            set_otp_policy,
        )
        self.assertEqual(reclaim_follow_after_otp("https://next.example/ok", "https://cont.example/otp", True), "https://next.example/ok")
        self.assertEqual(reclaim_follow_after_otp("", "https://cont.example/otp", True), "")
        self.assertEqual(reclaim_follow_after_otp("", "https://cont.example/consent", False), "https://cont.example/consent")
        client = SimpleNamespace(last_oauth_error="")
        token = set_otp_policy("reclaim")
        try:
            note_reclaim_otp_exhausted(client, object())
            self.assertEqual(client.last_oauth_error, "email_otp_exhausted")
            client.last_oauth_error = "email_otp_rejected_401"
            note_reclaim_otp_exhausted(client, object())
            self.assertEqual(client.last_oauth_error, "email_otp_rejected_401")
            client.last_oauth_error = ""
            note_reclaim_otp_exhausted(client, None)
            self.assertEqual(client.last_oauth_error, "")
        finally:
            reset_otp_policy(token)
        fresh = SimpleNamespace(last_oauth_error="")
        note_reclaim_otp_exhausted(fresh, object())
        self.assertEqual(fresh.last_oauth_error, "")
        with open("vendor/lib/oauth_client.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("reclaim_follow_after_otp(", source)
        self.assertGreaterEqual(source.count("note_reclaim_otp_exhausted("), 2)
        self.assertNotIn("if pwdless_continue_url:", source)

    def test_reclaim_otp_rate_limit_keeps_code_and_same_page_is_not_a_next_hop(self):
        from app.extract import preserve_login_code, reclaim_otp_next_url
        reason = preserve_login_code("email_otp_rejected_429", "邮箱验证码被限流，请稍后重试")
        self.assertIn("email_otp_rejected_429", reason)
        self.assertIn("邮箱验证码被限流", reason)
        self.assertEqual(
            reclaim_otp_next_url(
                "https://auth.openai.com/api/accounts/consent",
                "https://auth.openai.com/email-verification",
            ),
            "https://auth.openai.com/api/accounts/consent",
        )
        self.assertEqual(reclaim_otp_next_url("", "https://auth.openai.com/email-verification"), "")
        self.assertEqual(
            reclaim_otp_next_url(
                "https://auth.openai.com/email-verification",
                "https://auth.openai.com/email-verification",
            ),
            "",
        )
        self.assertEqual(
            reclaim_otp_next_url(
                "https://auth.openai.com/email-otp/send?x=1",
                "https://auth.openai.com/log-in",
            ),
            "",
        )
        with open("vendor/lib/oauth_client.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("reclaim_otp_next_url(", source)
        self.assertNotIn('return next_url or continue_url or ""', source)
        self.assertGreaterEqual(source.count("note_reclaim_otp_exhausted("), 3)
        with open("app/engine.py", encoding="utf-8") as handle:
            engine = handle.read()
        self.assertIn("preserve_login_code(", engine)

    def test_reclaim_otp_send_failure_is_not_password(self):
        from app.extract import (
            note_reclaim_otp_send_failure,
            note_reclaim_password_exhausted,
            reset_otp_policy,
            set_otp_policy,
        )
        client = SimpleNamespace(last_oauth_error="")
        token = set_otp_policy("reclaim")
        try:
            note_reclaim_otp_send_failure(client, 500, object())
            self.assertEqual(client.last_oauth_error, "email_otp_rejected_500")
            note_reclaim_password_exhausted(client, 401, object())
            self.assertEqual(client.last_oauth_error, "email_otp_rejected_500")
            client.last_oauth_error = ""
            note_reclaim_otp_send_failure(client, 0, object())
            self.assertEqual(client.last_oauth_error, "email_otp_exhausted")
            client.last_oauth_error = "email_otp_rejected_429"
            note_reclaim_otp_send_failure(client, 500, object())
            self.assertEqual(client.last_oauth_error, "email_otp_rejected_429")
            client.last_oauth_error = ""
            note_reclaim_otp_send_failure(client, 429, None)
            self.assertEqual(client.last_oauth_error, "")
        finally:
            reset_otp_policy(token)
        fresh = SimpleNamespace(last_oauth_error="")
        note_reclaim_otp_send_failure(fresh, 500, object())
        self.assertEqual(fresh.last_oauth_error, "")
        with open("vendor/lib/oauth_client.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertGreaterEqual(source.count("note_reclaim_otp_send_failure("), 2)

    def test_success_keeps_tokens_when_cancelled(self):
        from app.cancel import CancelState, install_cancel, reset_cancel
        from app.extract import success
        state = CancelState()
        state.stop.set()
        token = install_cancel(state)
        try:
            result = success(
                {"access_token": "kept-access", "refresh_token": "kept-refresh", "id_token": "kept-id"},
                {},
                None,
                "a@b.c",
            )
        finally:
            reset_cancel(token)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("accessToken"), "kept-access")
        self.assertEqual(result.get("refreshToken"), "kept-refresh")


if __name__ == "__main__":

    unittest.main()
