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

    def test_members_come_from_items_not_the_first_id_list(self):
        data = {
            "errors": [{"id": "not-a-person"}],
            "items": [{"id": "user-1", "email": "a@b.c", "role": "standard-user"}],
            "total": 1,
        }
        people = worker.member_page(data)
        self.assertEqual(people[0]["id"], "user-1")

    def test_missing_total_is_complete_when_pages_end(self):
        urls = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            urls.append(url)
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}]})
            if "/invites" in url:
                return FakeResponse(200, {"items": []})
            if "seat_type_counts" in url:
                return FakeResponse(200, {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5, "will_renew": True, "active_until": "2026-10-01T00:00:00Z"})
            raise AssertionError(url)

        original = worker.request_with_retry
        worker.request_with_retry = fake_retry
        try:
            result = worker.snapshot(object(), "token", "ws-1")
        finally:
            worker.request_with_retry = original
        self.assertTrue(result["complete"])
        self.assertTrue(any("/users/seat_type_counts" in url for url in urls))

    def test_total_mismatch_is_not_complete(self):
        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}], "total": 3})
            if "/invites" in url:
                return FakeResponse(200, {"items": []})
            if "seat_type_counts" in url:
                return FakeResponse(200, {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5})
            raise AssertionError(url)

        original = worker.request_with_retry
        worker.request_with_retry = fake_retry
        try:
            result = worker.snapshot(object(), "token", "ws-1")
        finally:
            worker.request_with_retry = original
        self.assertFalse(result["complete"])

    def test_non_2xx_member_page_is_not_complete(self):
        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            if "/users?" in url:
                return FakeResponse(404, {"error": "missing", "seats_entitled": 99})
            if "/invites" in url:
                return FakeResponse(200, {"items": []})
            if "seat_type_counts" in url:
                return FakeResponse(200, {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5})
            raise AssertionError(url)

        original = worker.request_with_retry
        worker.request_with_retry = fake_retry
        try:
            result = worker.snapshot(object(), "token", "ws-1")
        finally:
            worker.request_with_retry = original
        self.assertFalse(result["complete"])
        self.assertEqual(result["members"], [])

    def test_subscription_error_does_not_supply_seats(self):
        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}], "total": 1})
            if "/invites" in url:
                return FakeResponse(404, {"items": [], "seats_entitled": 99})
            if "seat_type_counts" in url:
                return FakeResponse(200, {})
            if "/subscriptions" in url:
                return FakeResponse(404, {"seats_entitled": 99, "will_renew": False})
            raise AssertionError(url)

        original = worker.request_with_retry
        worker.request_with_retry = fake_retry
        try:
            result = worker.snapshot(object(), "token", "ws-1")
        finally:
            worker.request_with_retry = original
        self.assertTrue(result["complete"])
        self.assertIsNone(result["seatsEntitled"])
        self.assertTrue(result["invitesTruncated"])

    def test_invites_are_paged(self):
        urls = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            urls.append(url)
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}]})
            if "/invites?" in url and "offset=0" in url:
                return FakeResponse(200, {"items": [{"id": f"i{n}", "email": f"u{n}@b.c", "role": "standard-user"} for n in range(100)]})
            if "/invites?" in url and "offset=100" in url:
                return FakeResponse(200, {"items": [{"id": "last", "email": "last@b.c", "role": "standard-user"}]})
            if "seat_type_counts" in url:
                return FakeResponse(200, {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5})
            raise AssertionError(url)

        original = worker.request_with_retry
        worker.request_with_retry = fake_retry
        try:
            result = worker.snapshot(object(), "token", "ws-1")
        finally:
            worker.request_with_retry = original
        self.assertTrue(any("offset=100" in url and "/invites" in url for url in urls))
        self.assertTrue(any(item["email"] == "last@b.c" for item in result["invites"]))

    def test_invite_count_keeps_only_the_emails_not_rejected(self):
        ok, bad = worker.invite_emails({"account_invites": 2, "errored_emails": ["c@b.c"]}, ["a@b.c", "b@b.c", "c@b.c"])
        self.assertEqual(bad, ["c@b.c"])
        self.assertEqual(ok, ["a@b.c", "b@b.c"])

    def test_invite_count_does_not_guess_when_it_does_not_match(self):
        ok, _bad = worker.invite_emails({"account_invites": 2, "errored_emails": []}, ["a@b.c", "b@b.c", "c@b.c"])
        self.assertEqual(ok, [])

    def test_invite_4xx_body_keeps_successes_and_seat_full(self):
        response = FakeResponse(400, {
            "account_invites": [{"email_address": "ok@example.com"}],
            "errored_emails": ["full@example.com"],
            "error": {"code": "seat_true_up_pending"},
        })
        outcome = worker.invite_outcome(response, ["ok@example.com", "full@example.com"])
        self.assertEqual(outcome["successes"], ["ok@example.com"])
        self.assertEqual(outcome["errored"], ["full@example.com"])
        self.assertTrue(outcome["seatFull"])
        self.assertFalse(outcome["stopped"])

    def test_invite_401_true_up_stops_for_seats_and_keeps_session(self):
        for payload in (
            {"error": {"code": "seat_true_up_pending"}, "account_invites": [{"email_address": "ok@example.com"}], "errored_emails": ["full@example.com"]},
            {"error": "true-up"},
            {"detail": "seat true_up required"},
        ):
            status, result = self.invite_with(FakeResponse(401, payload))
            self.assertEqual(status, 200, payload)
            self.assertTrue(result["ok"], payload)
            self.assertTrue(result["seatFull"], payload)
            self.assertFalse(result["stopped"], payload)
            self.assertNotEqual(result.get("code"), "SESSION_EXPIRED", payload)
            self.assertNotIn("session 已失效", result.get("message") or "", payload)
        status, result = self.invite_with(FakeResponse(401, {
            "account_invites": [{"email_address": "ok@example.com"}],
            "errored_emails": ["full@example.com"],
            "error": {"code": "seat_true_up_pending"},
        }))
        self.assertEqual(result["successes"], ["ok@example.com"])
        self.assertEqual(result["errored"], ["full@example.com"])

    def test_invite_401_workspace_stop_is_not_session_expired(self):
        status, result = self.invite_with(FakeResponse(403, {"error": {"code": "deactivated_workspace"}}))
        self.assertEqual(status, 200)
        self.assertTrue(result["stopped"])
        self.assertFalse(result["seatFull"])
        self.assertNotEqual(result.get("code"), "SESSION_EXPIRED")

    def test_invite_401_token_revoked_still_expires_session(self):
        with self.assertRaises(TeamCallError) as caught:
            self.invite_with(FakeResponse(401, {"error": "token_revoked"}))
        self.assertEqual(caught.exception.code, "SESSION_EXPIRED")

    def test_invite_html_403_stays_egress_blocked(self):
        with self.assertRaises(TeamCallError) as caught:
            self.invite_with(FakeResponse(403, "<html>seat_true_up_pending</html>"))
        self.assertEqual(caught.exception.code, "EGRESS_BLOCKED")

    def test_invite_plain_true_up_does_not_throw(self):
        response = FakeResponse(401, {"error": "placeholder"})
        response.text = "true-up"
        response.headers = {"content-type": "text/plain"}
        response.json = lambda: (_ for _ in ()).throw(ValueError("not json"))
        status, result = self.invite_with(response)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertTrue(result["seatFull"])
        self.assertNotIn("session 已失效", result.get("message") or "")

    def test_invite_5xx_true_up_stays_upstream(self):
        with self.assertRaises(TeamCallError) as caught:
            self.invite_with(FakeResponse(500, {"error": "seat_true_up_pending"}))
        self.assertEqual(caught.exception.code, "UPSTREAM")

    def test_invite_post_marks_sent_even_when_rejected(self):
        status, result = self.invite_with(FakeResponse(200, {
            "account_invites": [],
            "errored_emails": ["ok@example.com", "full@example.com"],
        }))
        self.assertEqual(status, 200)
        self.assertTrue(result["inviteSent"])
        status, result = self.invite_with(FakeResponse(401, {"error": "true-up"}))
        self.assertTrue(result["inviteSent"])

    def test_invite_post_error_marks_sent_for_the_handler(self):
        with self.assertRaises(TeamCallError) as caught:
            self.invite_with(FakeResponse(403, "<html>blocked</html>"))
        self.assertEqual(caught.exception.code, "EGRESS_BLOCKED")
        self.assertTrue(caught.exception.invite_sent)
        status, payload = worker.error_payload(caught.exception)
        self.assertEqual(payload["code"], "EGRESS_BLOCKED")
        self.assertTrue(payload["inviteSent"])
        self.assertNotIn("session 已失效", payload["message"])

    def test_invite_precheck_failure_is_not_sent(self):
        originals = (worker.open_session, worker.precheck)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="device")

        def blocked(http):
            raise TeamCallError("BANNED_EGRESS", "出口在封禁地区，已停止")

        worker.precheck = blocked
        try:
            with self.assertRaises(TeamCallError) as caught:
                worker.team_invite({
                    "session": {"accessToken": "personal-at"},
                    "workspaceId": "ws-1",
                    "emails": ["ok@example.com"],
                    "proxy": "socks5://127.0.0.1:1080",
                })
        finally:
            worker.open_session, worker.precheck = originals
        self.assertEqual(caught.exception.code, "BANNED_EGRESS")
        self.assertFalse(getattr(caught.exception, "invite_sent", False))
        status, payload = worker.error_payload(caught.exception)
        self.assertNotIn("inviteSent", payload)

    def invite_with(self, response):
        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            return response

        originals = (worker.open_session, worker.precheck, worker.living_access, worker.exchange_workspace, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="device")
        worker.precheck = lambda http: None
        worker.living_access = lambda http, session, workspace_id: "personal-at"
        worker.exchange_workspace = lambda http, token, workspace_id: {"accessToken": "workspace-at"}
        worker.request_with_retry = fake_retry
        try:
            return worker.team_invite({
                "session": {"accessToken": "personal-at", "sessionToken": "sess"},
                "workspaceId": "ws-1",
                "emails": ["ok@example.com", "full@example.com"],
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.living_access, worker.exchange_workspace, worker.request_with_retry = originals

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

    def test_usage_429_is_rate_limit_and_sends_version(self):
        captured = {}

        def fake_open(proxy):
            return SimpleNamespace(headers={})

        def fake_precheck(http):
            return None

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            captured["headers"] = headers
            return FakeResponse(429, {"error": "rate"})

        originals = (worker.open_session, worker.precheck, worker.request_with_retry)
        worker.open_session = fake_open
        worker.precheck = fake_precheck
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_usage({"accessToken": "child-at", "workspaceId": "ws-1", "proxy": "socks5://127.0.0.1:1080"})
        finally:
            worker.open_session, worker.precheck, worker.request_with_retry = originals
        self.assertNotEqual(result.get("usageStatus"), "exhausted")
        self.assertIsNot(result.get("limitReached"), True)
        self.assertEqual(result.get("code"), "RATE_LIMITED")
        self.assertEqual(captured["headers"].get("Version"), "0.146.0")

    def test_onboard_joins_on_the_login_session_and_returns_workspace_file(self):
        login_session = SimpleNamespace(headers={"Accept-Language": "en-US", "User-Agent": "ua"}, oai_device_id="child-device")
        calls = []

        def fake_login(email, password, totp, proxy, workspace_id=""):
            self.assertEqual(email, "kid@example.com")
            return login_session, {"access_token": "codex-at", "refresh_token": "codex-rt"}

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            calls.append((url, headers.get("Authorization"), http))
            if url.endswith("/api/auth/session"):
                raise AssertionError("上车不能用空 bearer 取网页 session")
            if "exchange_workspace_token" in url:
                self.assertIs(http, login_session)
                self.assertIn("codex-at", headers.get("Authorization", ""))
                token = jwt_with_account("ws-team", "user-9", "team")
                return FakeResponse(200, {"accessToken": token, "email": "kid@example.com"})
            if url.endswith("/invites/request") or url.endswith("/invites/accept") or "/accounts/check/" in url:
                self.assertIs(http, login_session)
                self.assertIn("codex-at", headers.get("Authorization", ""))
                return FakeResponse(200, {})
            raise AssertionError(url)

        originals = (worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session)
        worker.login_child = fake_login
        worker.request_with_retry = fake_retry
        worker.precheck = lambda http: None
        probe = SimpleNamespace(closed=False)
        probe.close = lambda: setattr(probe, "closed", True)
        worker.open_session = lambda proxy: probe
        try:
            _status, result = worker.team_onboard({
                "email": "kid@example.com",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "workspaceId": "ws-team",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session = originals
        self.assertTrue(probe.closed)
        self.assertTrue(result["ok"])
        self.assertEqual(result["accountId"], "ws-team")
        self.assertEqual(result["planType"], "team")
        self.assertNotIn("accounts", result["raw"])
        self.assertEqual(result["raw"]["credentials"]["chatgpt_account_id"], "ws-team")
        self.assertNotIn("codex-at", json.dumps(result))

    def test_kick_retries_with_login_then_mother(self):
        calls = []
        login_session = SimpleNamespace(headers={"Accept-Language": "en-US", "User-Agent": "ua"}, oai_device_id="child-device")

        def fake_open(proxy):
            return SimpleNamespace(headers={}, oai_device_id="mother-device", name="mother")

        def fake_login(email, password, totp, proxy, workspace_id=""):
            return login_session, {"access_token": "codex-at", "refresh_token": "rt"}

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            calls.append((method, url, headers.get("Authorization"), http))
            if method == "DELETE" and "stored-at" in headers.get("Authorization", ""):
                return FakeResponse(401, {"error": "token_revoked"})
            if url.endswith("/api/auth/session"):
                raise AssertionError("自退不能用空 bearer 取网页 session")
            if "exchange_workspace_token" in url and http is login_session:
                self.assertIn("codex-at", headers.get("Authorization", ""))
                return FakeResponse(200, {"accessToken": jwt_with_account("ws-team", "user-9", "team")})
            if method == "DELETE" and http is login_session:
                return FakeResponse(204, {})
            raise AssertionError((method, url))

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = fake_open
        worker.precheck = lambda http: None
        worker.login_child = fake_login
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "accessToken": "stored-at",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "email": "kid@example.com",
                "session": {"accessToken": "mother-at"},
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        deletes = [item for item in calls if item[0] == "DELETE"]
        self.assertEqual(len(deletes), 2)
        self.assertIn("stored-at", deletes[0][2])
        self.assertIs(deletes[1][3], login_session)
        self.assertNotIn("mother-at", deletes[1][2])

    def test_kick_gateonly_rejects_token_for_another_workspace(self):
        deletes = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization", "")
            if method == "DELETE" and "stored-at" in auth:
                return FakeResponse(401, {"error": "token_revoked"})
            if method == "GET" and ("exchange_workspace_token" in url or url.endswith("/api/auth/session")):
                return FakeResponse(403, "<html>cloudflare</html>")
            if method == "DELETE":
                deletes.append(auth)
                return FakeResponse(204, {})
            raise AssertionError(url)

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(get=lambda *args, **kwargs: None)
        worker.precheck = lambda http: None
        worker.request_with_retry = fake_retry
        worker.login_child = lambda *args: (SimpleNamespace(), {"access_token": jwt_with_account("other-ws", "user-9", "team")})
        try:
            _status, result = worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "accessToken": "stored-at",
                "email": "kid@example.com",
                "password": "chatgpt-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertFalse(result["ok"])
        self.assertEqual(deletes, [])

    def test_already_member_accept_400_still_exchanges(self):
        login_session = SimpleNamespace(headers={"Accept-Language": "en-US", "User-Agent": "ua"}, oai_device_id="child-device")

        def fake_login(email, password, totp, proxy, workspace_id=""):
            return login_session, {"access_token": "codex-at"}

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            if url.endswith("/api/auth/session"):
                raise AssertionError("上车不能用空 bearer 取网页 session")
            if url.endswith("/invites/accept"):
                return FakeResponse(400, {"error": "already_member"})
            if url.endswith("/invites/request") or "/accounts/check/" in url:
                return FakeResponse(200, {})
            if "exchange_workspace_token" in url:
                return FakeResponse(200, {"accessToken": jwt_with_account("ws-team", "user-9", "team")})
            raise AssertionError(url)

        originals = (worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session)
        worker.login_child = fake_login
        worker.request_with_retry = fake_retry
        worker.precheck = lambda http: None
        probe = SimpleNamespace(closed=False)
        probe.close = lambda: setattr(probe, "closed", True)
        worker.open_session = lambda proxy: probe
        try:
            _status, result = worker.team_onboard({
                "email": "kid@example.com",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "workspaceId": "ws-team",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session = originals
        self.assertTrue(probe.closed)
        self.assertTrue(result["ok"])
        self.assertEqual(result["accountId"], "ws-team")

    def test_pasted_cookies_refresh_access_before_mother_calls(self):
        jar = SimpleNamespace(items=[])

        def set_cookie(name, value, domain=""):
            jar.items.append((name, value, domain))

        jar.set = set_cookie
        http = SimpleNamespace(headers={}, oai_device_id="dev", cookies=jar)

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization")
            if url.endswith("/api/auth/session"):
                self.assertNotIn("Authorization", headers or {})
                return FakeResponse(200, {"accessToken": "fresh-at"})
            if "exchange_workspace_token" in url or "/users?" in url:
                self.assertIn("fresh-at", auth or "")
                self.assertNotIn("expired-at", auth or "")
                if "/users?" in url:
                    return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}]})
                return FakeResponse(200, {"accessToken": "fresh-at"})
            if "/invites" in url or "seat_type_counts" in url:
                return FakeResponse(200, {"items": []} if "/invites" in url else {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5})
            raise AssertionError(url)

        originals = (worker.open_session, worker.precheck, worker.request_with_retry)
        worker.open_session = lambda proxy: http
        worker.precheck = lambda http: None
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_snapshot({
                "session": {
                    "accessToken": "expired-at",
                    "cookies": [{"name": "oai-did", "value": "cookie-1", "domain": "chatgpt.com"}],
                },
                "workspaceId": "ws-1",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        self.assertTrue(any(name == "oai-did" and value == "cookie-1" for name, value, _domain in jar.items))
        self.assertFalse(any(name == "__Secure-next-auth.session-token" for name, value, _domain in jar.items))

    def test_session_token_replays_as_known_session_cookie(self):
        jar = SimpleNamespace(items=[])

        def set_cookie(name, value, domain=""):
            jar.items.append((name, value, domain))

        jar.set = set_cookie
        http = SimpleNamespace(headers={}, oai_device_id="dev", cookies=jar)
        session_calls = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization") or ""
            if url.endswith("/api/auth/session") and "exchange_workspace_token" not in url:
                session_calls.append(auth)
                self.assertNotIn("Bearer", auth)
                return FakeResponse(200, {"accessToken": "fresh-at"})
            self.assertIn("fresh-at", auth)
            self.assertNotIn("expired-at", auth)
            self.assertNotIn("live-session", auth)
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"id": "u1", "email": "a@b.c", "role": "account-owner"}]})
            if "exchange_workspace_token" in url:
                return FakeResponse(200, {"accessToken": "fresh-at"})
            if "/invites" in url or "seat_type_counts" in url:
                return FakeResponse(200, {"items": []} if "/invites" in url else {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"seats_entitled": 5})
            raise AssertionError(url)

        originals = (worker.open_session, worker.precheck, worker.request_with_retry)
        worker.open_session = lambda proxy: http
        worker.precheck = lambda http: None
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_snapshot({
                "session": {"accessToken": "expired-at", "sessionToken": "live-session"},
                "workspaceId": "ws-1",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        self.assertEqual(session_calls, [""])
        self.assertIn(("__Secure-next-auth.session-token", "live-session", ".chatgpt.com"), jar.items)

    def test_self_kick_login_locks_the_workspace(self):
        seen = {}

        def fake_login(email, password, totp, proxy, workspace_id=""):
            seen["workspace_id"] = workspace_id
            return SimpleNamespace(headers={}, oai_device_id="d"), {"access_token": jwt_with_account("other-ws", "user-9", "team")}

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization", "")
            if method == "DELETE" and "stored-at" in auth:
                return FakeResponse(401, {"error": "token_revoked"})
            if url.endswith("/api/auth/session"):
                return FakeResponse(403, "<html>blocked</html>")
            return FakeResponse(401, {"error": "no"})

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="mother")
        worker.precheck = lambda http: None
        worker.request_with_retry = fake_retry
        worker.login_child = fake_login
        try:
            worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "accessToken": "stored-at",
                "email": "kid@example.com",
                "password": "chatgpt-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertEqual(seen.get("workspace_id"), "ws-team")

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

    def test_nested_user_is_a_member_and_unparsed_row_is_incomplete(self):
        people = worker.member_page({"items": [{"user": {"id": "u2", "email": "b@c.d"}, "role": "standard-user"}]})
        self.assertEqual(people[0]["id"], "u2")
        self.assertEqual(people[0]["email"], "b@c.d")
        self.assertEqual(people[0]["role"], "standard-user")

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            if "/users?" in url:
                return FakeResponse(200, {"items": [{"user": {"email": "a@b.c"}}]})
            if "/invites" in url or "seat_type_counts" in url:
                return FakeResponse(200, {"items": []} if "/invites" in url else {})
            if "/subscriptions" in url:
                return FakeResponse(200, {"data": {"seats_entitled": 5, "will_renew": True}})
            if "exchange_workspace_token" in url:
                return FakeResponse(200, {"accessToken": "at"})
            raise AssertionError(url)

        originals = (worker.open_session, worker.precheck, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="dev")
        worker.precheck = lambda http: None
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_snapshot({
                "session": {"accessToken": "at"},
                "workspaceId": "ws-1",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.request_with_retry = originals
        self.assertFalse(result["complete"])
        self.assertEqual(result["seatsEntitled"], 5)
        self.assertEqual(result["willRenew"], True)
        self.assertEqual(result["members"], [])

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

    def test_onboard_stops_before_login_when_proxy_precheck_fails(self):
        order = []

        def fake_open(proxy):
            order.append("open")
            session = SimpleNamespace()
            session.close = lambda: order.append("close")
            return session

        def fake_precheck(http):
            order.append("precheck")
            raise TeamCallError("EGRESS_BLOCKED", "出口预检失败，已停止")

        def fake_login(*args, **kwargs):
            order.append("login")
            raise AssertionError("预检失败不能登录")

        originals = (worker.open_session, worker.precheck, worker.login_child)
        worker.open_session = fake_open
        worker.precheck = fake_precheck
        worker.login_child = fake_login
        try:
            _status, result = worker.team_onboard({
                "email": "kid@example.com",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "workspaceId": "ws-team",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child = originals
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "EGRESS_BLOCKED")
        self.assertEqual(order, ["open", "precheck", "close"])

    def test_kick_gateonly_cookie_delete_does_not_use_foreign_jwt(self):
        jar = SimpleNamespace(items=[("oai-did", "cookie-1", "chatgpt.com")])
        jar.set = lambda name, value, domain="": jar.items.append((name, value, domain))
        login_session = SimpleNamespace(headers={}, oai_device_id="child", cookies=jar)
        deletes = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization", "")
            if method == "DELETE" and "stored-at" in auth:
                return FakeResponse(401, {"error": "token_revoked"})
            if method == "GET" and ("exchange_workspace_token" in url or url.endswith("/api/auth/session")):
                return FakeResponse(403, "<html>cloudflare</html>")
            if method == "DELETE":
                deletes.append((url, auth, http))
                return FakeResponse(204, {})
            raise AssertionError(url)

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="mother")
        worker.precheck = lambda http: None
        worker.login_child = lambda *args: (login_session, {"access_token": jwt_with_account("other-ws", "user-from-token", "team")})
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "accessToken": "stored-at",
                "email": "kid@example.com",
                "password": "chatgpt-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        self.assertEqual(len(deletes), 1)
        self.assertIn("/accounts/ws-team/users/user-9", deletes[0][0])
        self.assertNotIn("user-from-token", deletes[0][0])
        self.assertNotIn("other-ws", deletes[0][1])
        self.assertEqual(deletes[0][1], "")
        self.assertIs(deletes[0][2], login_session)

    def test_gateonly_cookie_delete_when_login_has_no_personal_token(self):
        jar = SimpleNamespace(items=[("__Secure-next-auth.session-token", "session-cookie", ".chatgpt.com")])
        login_session = SimpleNamespace(headers={}, oai_device_id="child", cookies=jar)
        deletes = []

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization", "")
            if method == "DELETE" and "stored-at" in auth:
                return FakeResponse(401, {"error": "token_revoked"})
            if method == "DELETE":
                deletes.append((url, auth, http))
                return FakeResponse(204, {})
            raise AssertionError((method, url, auth))

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="mother")
        worker.precheck = lambda http: None
        worker.login_child = lambda *args: (login_session, {})
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "accessToken": "stored-at",
                "email": "kid@example.com",
                "password": "chatgpt-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "session": {"accessToken": "mother-at"},
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        self.assertNotIn("可能被限流", result.get("message") or "")
        self.assertEqual(len(deletes), 1)
        self.assertIn("/accounts/ws-team/users/user-9", deletes[0][0])
        self.assertEqual(deletes[0][1], "")
        self.assertIs(deletes[0][2], login_session)

    def test_mother_fallback_warns_rate_limit(self):
        class ReauthError(Exception):
            pass

        deletes = []

        def fake_login(*args, **kwargs):
            raise ReauthError("token 交换失败")

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            auth = (headers or {}).get("Authorization", "")
            if "exchange_workspace_token" in url:
                self.assertIn("mother-at", auth)
                return FakeResponse(200, {"accessToken": "mother-workspace"})
            if method == "DELETE":
                deletes.append(auth)
                return FakeResponse(204, {})
            raise AssertionError((method, url))

        originals = (worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry)
        worker.open_session = lambda proxy: SimpleNamespace(headers={}, oai_device_id="mother")
        worker.precheck = lambda http: None
        worker.login_child = fake_login
        worker.request_with_retry = fake_retry
        try:
            _status, result = worker.team_kick({
                "workspaceId": "ws-team",
                "userId": "user-9",
                "email": "kid@example.com",
                "password": "chatgpt-pass",
                "totp": "JBSWY3DPEHPK3PXP",
                "session": {"accessToken": "mother-at"},
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.open_session, worker.precheck, worker.login_child, worker.request_with_retry = originals
        self.assertTrue(result["ok"])
        self.assertIn("可能被限流", result.get("message") or "")
        self.assertTrue(result.get("rateLimited"))
        self.assertTrue(any("mother-workspace" in item or "mother-at" in item for item in deletes))

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

    def test_onboard_cookie_only_joins_without_fetching_plain_session(self):
        login_session = SimpleNamespace(
            headers={"Accept-Language": "en-US", "User-Agent": "ua"},
            oai_device_id="child-device",
            cookies=SimpleNamespace(items=[("__Secure-next-auth.session-token", "session-cookie")]),
        )
        calls = []

        def fake_login(email, password, totp, proxy, workspace_id=""):
            return login_session, {}

        def fake_retry(http, method, url, headers=None, payload=None, form=None):
            calls.append(url)
            auth = (headers or {}).get("Authorization")
            self.assertIs(http, login_session)
            self.assertFalse(auth)
            if url.endswith("/api/auth/session"):
                raise AssertionError("上车不能用空 bearer 取网页 session")
            if "exchange_workspace_token" in url:
                return FakeResponse(200, {"accessToken": jwt_with_account("ws-team", "user-9", "team")})
            if url.endswith("/invites/request") or url.endswith("/invites/accept") or "/accounts/check/" in url:
                return FakeResponse(200, {})
            raise AssertionError(url)

        originals = (worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session)
        worker.login_child = fake_login
        worker.request_with_retry = fake_retry
        worker.precheck = lambda http: None
        probe = SimpleNamespace(closed=False)
        probe.close = lambda: setattr(probe, "closed", True)
        worker.open_session = lambda proxy: probe
        try:
            _status, result = worker.team_onboard({
                "email": "kid@example.com",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "workspaceId": "ws-team",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session = originals
        self.assertTrue(probe.closed)
        self.assertTrue(result["ok"])
        self.assertEqual(result["accountId"], "ws-team")
        self.assertTrue(any(url.endswith("/invites/request") for url in calls))
        self.assertTrue(any(url.endswith("/invites/accept") for url in calls))
        self.assertTrue(any("/accounts/check/" in url for url in calls))
        self.assertTrue(any("exchange_workspace_token" in url for url in calls))

    def test_onboard_without_token_or_cookies_still_fails(self):
        login_session = SimpleNamespace(headers={}, oai_device_id="child-device", cookies=SimpleNamespace(items=[]))

        def fake_retry(*args, **kwargs):
            raise AssertionError("没有登录凭据不能发请求")

        originals = (worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session)
        worker.login_child = lambda *args, **kwargs: (login_session, {})
        worker.request_with_retry = fake_retry
        worker.precheck = lambda http: None
        probe = SimpleNamespace(closed=False)
        probe.close = lambda: setattr(probe, "closed", True)
        worker.open_session = lambda proxy: probe
        try:
            _status, result = worker.team_onboard({
                "email": "kid@example.com",
                "password": "secret",
                "totp": "JBSWY3DPEHPK3PXP",
                "workspaceId": "ws-team",
                "proxy": "socks5://127.0.0.1:1080",
            })
        finally:
            worker.login_child, worker.request_with_retry, worker.precheck, worker.open_session = originals
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "AUTH")
        self.assertIn("登录后没有拿到 ChatGPT session", result["message"])

    def test_invite_id_rows_are_listed_and_not_truncated(self):
        def snapshot_with(invite_payload):
            def fake_retry(http, method, url, headers=None, payload=None, form=None):
                if "/users?" in url:
                    return FakeResponse(200, {"items": [{"id": "owner", "email": "mother@example.com", "role": "account-owner"}], "total": 1})
                if "/invites?" in url:
                    return FakeResponse(200, invite_payload)
                if "seat_type_counts" in url:
                    return FakeResponse(200, {})
                if "/subscriptions" in url:
                    return FakeResponse(200, {"seats_entitled": 5})
                raise AssertionError(url)

            original = worker.request_with_retry
            worker.request_with_retry = fake_retry
            try:
                return worker.snapshot(object(), "token", "ws-1")
            finally:
                worker.request_with_retry = original

        by_items = snapshot_with({"items": [{"invite_id": "inv-1", "email_address": "kid@example.com"}]})
        self.assertFalse(by_items["invitesTruncated"])
        self.assertEqual(by_items["invites"], [{"id": "inv-1", "email": "kid@example.com"}])
        self.assertEqual([item["id"] for item in by_items["members"]], ["owner"])

        by_key = snapshot_with({"invites": [{"invite_id": "inv-2", "email_address": "other@example.com"}]})
        self.assertFalse(by_key["invitesTruncated"])
        self.assertEqual(by_key["invites"], [{"id": "inv-2", "email": "other@example.com"}])

    def test_handler_logs_exception_class_without_body(self):
        import io
        from contextlib import redirect_stdout

        original_route = worker.ROUTES["/internal/team/usage"]
        original_token = worker.TOKEN

        def boom(_body):
            raise RuntimeError("secret-body-token")

        worker.ROUTES["/internal/team/usage"] = boom
        worker.TOKEN = "team-token"
        sent = {}
        handler = worker.Handler.__new__(worker.Handler)
        handler.path = "/internal/team/usage"
        handler.headers = {"Authorization": "Bearer team-token", "Content-Length": "40"}
        handler.rfile = io.BytesIO(b'{"accessToken":"secret-body-token"}')
        handler._send = lambda status, payload: sent.update(status=status, payload=payload)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                handler.do_POST()
        finally:
            worker.ROUTES["/internal/team/usage"] = original_route
            worker.TOKEN = original_token
        self.assertEqual(sent["payload"]["message"], "协议服务处理失败")
        log = buf.getvalue()
        self.assertIn("RuntimeError", log)
        self.assertIn("/internal/team/usage", log)
        self.assertNotIn("secret-body-token", log)


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


if __name__ == "__main__":
    unittest.main()
