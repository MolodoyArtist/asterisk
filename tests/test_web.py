import http.client
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpnctl import web
from vpnctl.common import hash_password, random_token


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        auth_file = Path(cls.tempdir.name) / "auth.json"
        auth_file.write_text(
            json.dumps(
                {
                    "username": "member-test",
                    "password": hash_password("correct horse battery staple"),
                    "session_secret": random_token(32),
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


if __name__ == "__main__":
    unittest.main()
