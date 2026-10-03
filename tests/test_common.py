import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpnctl.agent import AgentError, check_domain, dispatch
from vpnctl.common import (
    ValidationError,
    b64url,
    client_uri,
    hash_password,
    make_session,
    redact_log,
    render_nginx,
    render_xray,
    validate_domain,
    validate_name,
    validate_state,
    verify_password,
    verify_session,
)

STATE = {
    "public_ip": "192.0.2.10",
    "public_ipv6": None,
    "ip_mode": True,
    "domain": None,
    "xhttp_path": "A_random_path_with_enough_entropy",
    "clients": [{"name": "phone", "id": "00000000-0000-4000-8000-000000000001", "enabled": True}],
}


class CommonTests(unittest.TestCase):
    def test_password_hash_and_session(self):
        record = hash_password("a sufficiently long password")
        self.assertTrue(verify_password("a sufficiently long password", record))
        self.assertFalse(verify_password("wrong password", record))
        session_key = b64url(b"0123456789abcdef0123456789abcdef")
        token, csrf = make_session("member", session_key)
        payload = verify_session(token, session_key)
        self.assertEqual(payload["csrf"], csrf)
        self.assertIsNone(verify_session(token + "x", session_key))

    def test_validation(self):
        self.assertEqual(validate_domain("Access.Example.COM."), "access.example.com")
        self.assertEqual(validate_name("phone-1"), "phone-1")
        for value in ("localhost", "bad domain", "-bad.example"):
            with self.assertRaises(ValidationError):
                validate_domain(value)

    def test_uri_uses_xhttp_and_tls(self):
        uri = client_uri(STATE, STATE["clients"][0])
        self.assertIn("type=xhttp", uri)
        self.assertIn("security=tls", uri)
        self.assertIn("192.0.2.10", uri)
        self.assertNotIn("sni=", uri)
        domain_state = dict(STATE, domain="access.example.com")
        domain_uri = client_uri(domain_state, STATE["clients"][0])
        self.assertIn("sni=access.example.com", domain_uri)
        self.assertIn("host=access.example.com", domain_uri)

    def test_rendered_xray_has_no_access_log(self):
        config = json.loads(render_xray(STATE))
        self.assertEqual(config["log"]["access"], "none")
        self.assertEqual(config["log"]["error"], "none")
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertIn("geoip:private", config["routing"]["rules"][0]["ip"])

    def test_nginx_masks_unknown_hosts_and_paths(self):
        state = dict(STATE, domain="access.example.com")
        config = render_nginx(state)
        self.assertIn("access_log off", config)
        self.assertIn("error_page 400 404 405 =404", config)
        self.assertIn("error_page 404 = @vpnctl_not_found", config)
        self.assertIn("limit_req zone=vpnctl_login", config)
        self.assertIn("client_max_body_size 0", config)
        self.assertIn("client_max_body_size 16k", config)
        self.assertIn("server_name access.example.com", config)
        self.assertIn('if ($host != "192.0.2.10")', config)
        self.assertEqual(config.count("listen 443 ssl http2 default_server"), 1)

    def test_redaction(self):
        value = "from 192.0.2.10 id 00000000-0000-4000-8000-000000000001 vless://secret@example.com"
        cleaned = redact_log(value)
        self.assertNotIn("192.0.2.10", cleaned)
        self.assertNotIn("00000000", cleaned)
        self.assertNotIn("vless://", cleaned)

    def test_domain_must_point_only_to_this_server(self):
        state = dict(STATE, public_ipv6="2001:db8::10")
        with mock.patch("vpnctl.agent.resolve_domain", return_value={"a": ["192.0.2.10"], "aaaa": ["2001:db8::10"]}):
            result = check_domain(state, "access.example.com")
            self.assertEqual(result["domain"], "access.example.com")
        with (
            mock.patch("vpnctl.agent.resolve_domain", return_value={"a": ["192.0.2.10", "198.51.100.8"], "aaaa": []}),
            self.assertRaises(AgentError),
        ):
            check_domain(state, "access.example.com")

    def test_state_integrity_validation(self):
        valid = dict(STATE, schema=1)
        validate_state(valid)
        duplicate = dict(valid, clients=[valid["clients"][0], dict(valid["clients"][0])])
        with self.assertRaises(ValidationError):
            validate_state(duplicate)
        weak_path = dict(valid, xhttp_path="short")
        with self.assertRaises(ValidationError):
            validate_state(weak_path)

    def test_password_reset_is_root_only(self):
        with self.assertRaises(AgentError):
            dispatch({"action": "reset_password", "payload": {}}, peer_uid=1000)

    def test_xray_restart_does_not_restart_control_plane(self):
        unit = (Path(__file__).resolve().parents[1] / "systemd" / "vpnctl-agent.service").read_text()
        self.assertIn("Wants=nginx.service xray.service", unit)
        self.assertNotIn("Requires=nginx.service xray.service", unit)


if __name__ == "__main__":
    unittest.main()
