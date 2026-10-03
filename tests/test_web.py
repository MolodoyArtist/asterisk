import base64
import http.client
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpnctl import web
from vpnctl.common import hash_password, make_session, random_token
from vpnctl.rpc import RPCError


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        auth_file = Path(cls.tempdir.name) / "auth.json"
        cls.auth_file = auth_file
        cls.session_secret = random_token(32)
        auth_file.write_text(
            json.dumps(
                {
                    "username": "member-test",
                    "password": hash_password("correct horse battery staple"),
                    "session_secret": cls.session_secret,
                }
            )
        )
        web.AUTH_FILE = auth_file
        try:
            cls.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        except PermissionError as exc:
            raise unittest.SkipTest("local sandbox does not allow loopback sockets") from exc
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tempdir.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read().decode("utf-8", "replace")
        headers_out = dict(response.getheaders())
        connection.close()
        return response.status, headers_out, data

    def authenticated_headers(self):
        token, csrf = make_session("member-test", self.session_secret)
        return {"Cookie": f"__Host-session={token}"}, csrf

    def test_public_root_is_only_generic_login(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Login", body)
        self.assertIn("Password", body)
        for forbidden in ("VPN", "Xray", "VLESS", "proxy"):
            self.assertNotIn(forbidden, body)
        self.assertIn("no-store", headers["Cache-Control"])

    def test_unknown_public_path_is_not_login(self):
        status, _, body = self.request("GET", "/random-probe")
        self.assertEqual(status, 404)
        self.assertNotIn("Login", body)
        status, _, body = self.request("POST", "/random-probe", "test=1", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 404)
        self.assertNotIn("Login", body)

    def test_valid_login_sets_hardened_cookie(self):
        body = urllib.parse.urlencode({"username": "member-test", "password": "correct horse battery staple"})
        status, headers, _ = self.request(
            "POST",
            "/login",
            body,
            {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-session="))
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_add_device_redirects_after_success(self):
        headers, csrf = self.authenticated_headers()
        body = urllib.parse.urlencode({"name": "tablet", "csrf": csrf})
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        with mock.patch("vpnctl.web.call", return_value={"name": "tablet", "uri": "vless://test"}) as call:
            status, response_headers, _ = self.request("POST", "/clients/add", body, headers)
        self.assertEqual(status, 303)
        self.assertEqual(response_headers["Location"], "/clients")
        call.assert_called_once_with("client_add", {"name": "tablet"})

    def test_mutation_requires_authentication_and_csrf(self):
        body = urllib.parse.urlencode({"name": "tablet"})
        base_headers = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))}
        status, response_headers, _ = self.request("POST", "/clients/add", body, base_headers)
        self.assertEqual(status, 303)
        self.assertEqual(response_headers["Location"], "/")

        headers, _ = self.authenticated_headers()
        headers.update(base_headers)
        with mock.patch("vpnctl.web.call") as call:
            status, _, response_body = self.request("POST", "/clients/add", body, headers)
        self.assertEqual(status, 403)
        self.assertIn("Request expired", response_body)
        call.assert_not_called()

    def test_logout_requires_csrf(self):
        headers, csrf = self.authenticated_headers()
        status, _, body = self.request("POST", "/logout", "", {**headers, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "0"})
        self.assertEqual(status, 403)
        self.assertIn("Request expired", body)
        body = urllib.parse.urlencode({"csrf": csrf})
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        status, response_headers, _ = self.request("POST", "/logout", body, headers)
        self.assertEqual(status, 303)
        self.assertEqual(response_headers["Location"], "/")

    def test_agent_failure_returns_page_instead_of_dropping_connection(self):
        headers, csrf = self.authenticated_headers()
        body = urllib.parse.urlencode({"name": "tablet", "csrf": csrf})
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        with mock.patch("vpnctl.web.call", side_effect=RPCError("temporarily unavailable")):
            status, _, response_body = self.request("POST", "/clients/add", body, headers)
        self.assertEqual(status, 400)
        self.assertIn("temporarily unavailable", response_body)

    def test_malformed_agent_result_returns_502_instead_of_dropping_connection(self):
        headers, _ = self.authenticated_headers()
        with mock.patch("vpnctl.web.call", return_value={}):
            status, _, response_body = self.request("GET", "/domain", headers=headers)
        self.assertEqual(status, 502)
        self.assertIn("Temporarily unavailable", response_body)

    def test_invalid_and_oversized_content_lengths_are_rejected(self):
        for length, expected in (("invalid", 400), ("-1", 400), (str(web.MAX_FORM_BYTES + 1), 413)):
            status, _, _ = self.request("POST", "/login", headers={"Content-Length": length})
            self.assertEqual(status, expected)

    def test_invalid_qr_payload_returns_error_page(self):
        headers, _ = self.authenticated_headers()
        with mock.patch("vpnctl.web.call", return_value={"png": "not base64!"}):
            status, _, response_body = self.request("GET", "/qr?name=phone", headers=headers)
        self.assertEqual(status, 400)
        self.assertIn("invalid QR code", response_body)

    def test_xhttp_qr_requests_the_xhttp_profile(self):
        headers, _ = self.authenticated_headers()
        png = base64.b64encode(b"test-png").decode()
        with mock.patch("vpnctl.web.call", return_value={"png": png}) as call:
            status, _, body = self.request("GET", "/qr?name=phone&profile=xhttp", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body, "test-png")
        call.assert_called_once_with("client_qr", {"name": "phone", "profile": "xhttp"})

    def test_domain_workflow_moves_to_domain_after_activation(self):
        headers, csrf = self.authenticated_headers()
        status_result = {
            "domain": None,
            "public_ip": "192.0.2.10",
            "public_ipv6": None,
        }
        with mock.patch("vpnctl.web.call", return_value=status_result):
            status, response_headers, _ = self.request("GET", "/domain", headers=headers)
        self.assertEqual(status, 200)
        self.assertNotIn("Location", response_headers)

        body = urllib.parse.urlencode({"domain": "access.example.com", "csrf": csrf})
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        with mock.patch("vpnctl.web.call", return_value={"domain": "access.example.com"}):
            status, response_headers, _ = self.request("POST", "/domain/check", body, headers)
        self.assertEqual(status, 303)
        self.assertTrue(response_headers["Location"].startswith("/domain?"))
        self.assertFalse(response_headers["Location"].startswith("https://"))

        with mock.patch("vpnctl.web.call", return_value={"domain": "access.example.com"}):
            status, response_headers, _ = self.request("POST", "/domain/add", body, headers)
        self.assertEqual(status, 303)
        self.assertEqual(response_headers["Location"], "https://access.example.com:8443/domain?added=1")

    def test_telegram_workflow_requires_csrf_and_stays_local(self):
        headers, csrf = self.authenticated_headers()
        with mock.patch("vpnctl.web.call", return_value={"enabled": False, "active": False}):
            status, _, body = self.request("GET", "/telegram", headers=headers)
        self.assertEqual(status, 200)
        self.assertIn("Optional MTProto", body)
        body = urllib.parse.urlencode({"csrf": csrf})
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        with mock.patch("vpnctl.web.call", return_value={"enabled": True}) as call:
            status, response_headers, _ = self.request("POST", "/telegram/enable", body, headers)
        self.assertEqual(status, 303)
        self.assertEqual(response_headers["Location"], "/telegram?enabled=1")
        call.assert_called_once_with("telegram_enable", {})

    def test_telegram_qr_uses_dedicated_agent_action(self):
        headers, _ = self.authenticated_headers()
        png = base64.b64encode(b"telegram-png").decode()
        with mock.patch("vpnctl.web.call", return_value={"png": png}) as call:
            status, _, body = self.request("GET", "/telegram/qr", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body, "telegram-png")
        call.assert_called_once_with("telegram_qr")

    def test_unreadable_auth_file_returns_503_without_leaking_hash_slot(self):
        original = web.AUTH_FILE
        web.AUTH_FILE = Path(self.tempdir.name) / "missing.json"
        try:
            body = urllib.parse.urlencode({"username": "member-test", "password": "correct horse battery staple"})
            status, _, response_body = self.request(
                "POST",
                "/login",
                body,
                {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
            )
            self.assertEqual(status, 503)
            self.assertIn("Temporarily unavailable", response_body)
            first = web.LOGIN_HASH_SLOTS.acquire(blocking=False)
            second = web.LOGIN_HASH_SLOTS.acquire(blocking=False)
            self.assertTrue(first and second)
            if second:
                web.LOGIN_HASH_SLOTS.release()
            if first:
                web.LOGIN_HASH_SLOTS.release()
        finally:
            web.AUTH_FILE = original


if __name__ == "__main__":
    unittest.main()
