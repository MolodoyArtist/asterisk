import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpnctl.agent import (
    AgentError,
    action_client_add,
    action_client_qr,
    action_domain_add,
    action_ip_disable,
    action_reset_password,
    action_telegram_enable,
    action_telegram_rotate,
    check_domain,
    dispatch,
)
from vpnctl.common import (
    ValidationError,
    atomic_write,
    b64url,
    client_uri,
    hash_password,
    make_session,
    redact_log,
    render_nginx,
    render_xray,
    telegram_uri,
    validate_domain,
    validate_name,
    validate_state,
    verify_password,
    verify_session,
)
from vpnctl.migrate import migrate_state

STATE = {
    "public_ip": "192.0.2.10",
    "public_ipv6": None,
    "domain": None,
    "xhttp_path": "A_random_path_with_enough_entropy",
    "reality": {
        "target": "www.example.com",
        "server_name": "www.example.com",
        "private_key": "private-key",
        "public_key": "public-key",
        "short_id": "a1b2c3d4",
    },
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

    def test_atomic_write_sets_mode_and_owner_before_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.json"
            path.write_text("old")
            atomic_write(path, "new", 0o640, (os.getuid(), os.getgid()))
            self.assertEqual(path.read_text(), "new")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.getuid(), os.getgid()))

    def test_validation(self):
        self.assertEqual(validate_domain("Access.Example.COM."), "access.example.com")
        self.assertEqual(validate_name("phone-1"), "phone-1")
        for value in ("localhost", "bad domain", "-bad.example", "192.0.2.10"):
            with self.assertRaises(ValidationError):
                validate_domain(value)

    def test_uri_uses_reality_and_domain_xhttp(self):
        uri = client_uri(STATE, STATE["clients"][0])
        self.assertIn("type=tcp", uri)
        self.assertIn("security=reality", uri)
        self.assertIn("flow=xtls-rprx-vision", uri)
        self.assertIn("192.0.2.10", uri)
        domain_state = dict(STATE, domain="access.example.com")
        domain_uri = client_uri(domain_state, STATE["clients"][0], "xhttp")
        self.assertIn("type=xhttp", domain_uri)
        self.assertIn("security=tls", domain_uri)
        self.assertIn(":8443", domain_uri)
        self.assertIn("sni=access.example.com", domain_uri)
        self.assertIn("host=access.example.com", domain_uri)

    def test_telegram_uri_uses_separate_port_and_padding_secret(self):
        state = dict(STATE, schema=2, telegram={"enabled": True, "port": 8444, "secret": "0123456789abcdef0123456789abcdef"})
        uri = telegram_uri(state)
        self.assertIn("server=192.0.2.10", uri)
        self.assertIn("port=8444", uri)
        self.assertIn("secret=dd0123456789abcdef0123456789abcdef", uri)
        with self.assertRaises(ValidationError):
            validate_state(dict(state, telegram={"enabled": True, "port": 443, "secret": "0123456789abcdef0123456789abcdef"}))

    def test_rendered_xray_has_no_access_log(self):
        config = json.loads(render_xray(STATE))
        self.assertEqual(config["log"]["access"], "none")
        self.assertEqual(config["log"]["error"], "none")
        self.assertEqual(config["inbounds"][0]["port"], 443)
        self.assertEqual(config["inbounds"][0]["streamSettings"]["security"], "reality")
        self.assertIn("geoip:private", config["routing"]["rules"][0]["ip"])

    def test_nginx_masks_unknown_hosts_and_paths(self):
        state = dict(STATE, domain="access.example.com")
        config = render_nginx(state)
        self.assertIn("access_log off", config)
        self.assertIn("error_page 400 404 405 =404", config)
        self.assertIn("error_page 404 = @not_found", config)
        self.assertIn("limit_req zone=vpnctl_login", config)
        self.assertIn("limit_conn_zone $binary_remote_addr zone=vpnctl_xhttp_conn", config)
        self.assertIn("limit_conn vpnctl_xhttp_conn 32", config)
        self.assertIn("client_max_body_size 0", config)
        self.assertIn("client_max_body_size 16k", config)
        self.assertIn("server_name access.example.com", config)
        self.assertIn("server_name _;", config)
        self.assertEqual(config.count("listen 8443 ssl http2 default_server"), 1)
        self.assertIn("/etc/letsencrypt/live/access.example.com/fullchain.pem", config)

    def test_redaction(self):
        value = "from 192.0.2.10 id 00000000-0000-4000-8000-000000000001 vless://secret@example.com tg://proxy?secret=secret MTPROXY_SECRET=0123456789abcdef0123456789abcdef"
        cleaned = redact_log(value)
        self.assertNotIn("192.0.2.10", cleaned)
        self.assertNotIn("00000000", cleaned)
        self.assertNotIn("vless://", cleaned)
        self.assertNotIn("tg://", cleaned)
        self.assertNotIn("0123456789abcdef", cleaned)

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
        valid = dict(STATE, schema=2)
        validate_state(valid)
        duplicate = dict(valid, clients=[valid["clients"][0], dict(valid["clients"][0])])
        with self.assertRaises(ValidationError):
            validate_state(duplicate)
        weak_path = dict(valid, xhttp_path="short")
        with self.assertRaises(ValidationError):
            validate_state(weak_path)
        for invalid in (
            dict(valid, domain="Access.Example.COM"),
            dict(valid, clients=[dict(valid["clients"][0], enabled="yes")]),
        ):
            with self.assertRaises(ValidationError):
                validate_state(invalid)

    def test_v1_state_migration_preserves_devices_and_domain(self):
        old = dict(STATE, schema=1, domain="access.example.com", ip_mode=True)
        old.pop("reality")
        migrated = migrate_state(old)
        self.assertEqual(migrated["schema"], 2)
        self.assertEqual(migrated["clients"], old["clients"])
        self.assertEqual(migrated["domain"], "access.example.com")
        self.assertNotIn("ip_mode", migrated)
        self.assertEqual(migrated["layout"], "legacy-xhttp-primary")
        self.assertIn(":443?", client_uri(migrated, migrated["clients"][0], "xhttp"))
        self.assertIn("listen 443 ssl http2 default_server", render_nginx(migrated))
        with self.assertRaises(ValidationError):
            client_uri(migrated, migrated["clients"][0], "reality")
        config = json.loads(render_xray(migrated))
        self.assertEqual([inbound["port"] for inbound in config["inbounds"]], [5555])

    def test_domain_first_nginx_uses_local_default_certificate(self):
        state = dict(STATE, schema=2, layout="reality-primary", domain="access.example.com")
        config = render_nginx(state)
        self.assertIn("listen 8443 ssl http2 default_server", config)
        self.assertIn("/etc/vpnctl/tls/default.crt", config)
        self.assertNotIn("/etc/letsencrypt/live/192.0.2.10/fullchain.pem", config)

    def test_password_reset_is_root_only(self):
        with self.assertRaises(AgentError):
            dispatch({"action": "reset_password", "payload": {}}, peer_uid=1000)

    def test_dispatch_rejects_invalid_payload_shapes(self):
        for request in ([], {"action": "status", "payload": []}):
            with self.assertRaises(AgentError):
                dispatch(request)  # type: ignore[arg-type]

    def test_client_mutation_rolls_back_after_restart_failure(self):
        original = dict(STATE, schema=2)
        with (
            mock.patch("vpnctl.agent.load_state", return_value=original),
            mock.patch("vpnctl.agent.validate_and_install_xray") as install_xray,
            mock.patch("vpnctl.agent.save_state") as save_state,
            mock.patch("vpnctl.agent.run", side_effect=[mock.Mock(returncode=1), mock.Mock(returncode=0)]),
            self.assertRaisesRegex(AgentError, "previous configuration was restored"),
        ):
            action_client_add({"name": "tablet"})
        self.assertEqual(install_xray.call_count, 2)
        self.assertEqual(save_state.call_count, 2)
        self.assertEqual(save_state.call_args_list[-1].args[0], original)

    def test_domain_add_restores_nginx_when_state_write_fails(self):
        original = dict(STATE, schema=2)
        expected_original = json.loads(json.dumps(original))
        with (
            mock.patch("vpnctl.agent.load_state", return_value=original),
            mock.patch("vpnctl.agent.check_domain", return_value={"domain": "access.example.com"}),
            mock.patch("vpnctl.agent.run", return_value=mock.Mock(returncode=0)),
            mock.patch("vpnctl.agent.validate_and_install_xray") as install_xray,
            mock.patch("vpnctl.agent.install_nginx") as install_nginx,
            mock.patch("vpnctl.agent.save_state", side_effect=OSError("disk full")),
            self.assertRaisesRegex(OSError, "disk full"),
        ):
            action_domain_add({"domain": "access.example.com"})
        self.assertEqual(install_nginx.call_count, 2)
        self.assertEqual(install_xray.call_count, 2)
        self.assertEqual(install_nginx.call_args_list[0].args[0]["domain"], "access.example.com")
        self.assertEqual(install_nginx.call_args_list[1].args[0], expected_original)

    def test_ip_panel_access_cannot_be_disabled(self):
        with self.assertRaisesRegex(AgentError, "cannot be disabled"):
            action_ip_disable({})

    def test_password_reset_writes_with_service_owner_atomically(self):
        auth = {"username": "member-test", "password": {}, "session_secret": "old"}
        user = mock.Mock(pw_uid=123)
        group = mock.Mock(gr_gid=456)
        with (
            mock.patch("vpnctl.agent.read_json", return_value=auth),
            mock.patch("vpnctl.agent.random_token", side_effect=["new-password-token", "new-session-secret"]),
            mock.patch("vpnctl.agent.hash_password", return_value={"hash": "new"}),
            mock.patch("vpnctl.agent.pwd.getpwnam", return_value=user),
            mock.patch("vpnctl.agent.grp.getgrnam", return_value=group),
            mock.patch("vpnctl.agent.write_json") as write_json,
        ):
            result = action_reset_password({})
        self.assertEqual(result["password"], "new-password-token")
        self.assertEqual(write_json.call_args.args[3], (123, 456))

    def test_qr_timeout_is_reported(self):
        with (
            mock.patch("vpnctl.agent.load_state", return_value=STATE),
            mock.patch("vpnctl.agent.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("qrencode", 15)),
            self.assertRaisesRegex(AgentError, "timed out"),
        ):
            action_client_qr({"name": "phone"})

    def test_telegram_enable_does_not_touch_xray_or_nginx(self):
        original = dict(STATE, schema=2)
        calls = []

        def fake_run(command, timeout=60):
            calls.append(command)
            return mock.Mock(returncode=0)

        with (
            mock.patch("vpnctl.agent.load_state", return_value=original),
            mock.patch("vpnctl.agent.run", side_effect=fake_run),
            mock.patch("vpnctl.agent._port_is_busy", return_value=False),
            mock.patch("vpnctl.agent._mtproxy_unit") as unit,
            mock.patch("vpnctl.agent.save_state") as save_state,
            mock.patch("vpnctl.agent.os.uname", return_value=mock.Mock(machine="x86_64")),
        ):
            result = action_telegram_enable({})
        self.assertTrue(result["enabled"])
        self.assertIn("port=8444", result["uri"])
        unit.assert_called_once_with("vpnctl-mtproxy-provision.service", 900)
        self.assertFalse(any("xray" in command or "nginx" in command for command in calls))
        self.assertTrue(save_state.called)

    def test_telegram_rotation_restores_secret_when_restart_fails(self):
        original = dict(STATE, schema=2, telegram={"enabled": True, "port": 8444, "secret": "0123456789abcdef0123456789abcdef"})
        with (
            mock.patch("vpnctl.agent.load_state", return_value=original),
            mock.patch("vpnctl.agent._mtproxy_unit") as unit,
            mock.patch("vpnctl.agent.run", side_effect=[mock.Mock(returncode=1), mock.Mock(returncode=0)]),
            mock.patch("vpnctl.agent.save_state"),
            self.assertRaisesRegex(AgentError, "previous secret was restored"),
        ):
            action_telegram_rotate({})
        self.assertEqual(unit.call_count, 2)
        self.assertEqual(unit.call_args_list[-1].args, ("vpnctl-mtproxy-configure.service", 60))

    def test_telegram_enable_rolls_back_state_and_cleanup_when_provision_fails(self):
        original = dict(STATE, schema=2)
        commands = []

        def fake_run(command, timeout=60):
            commands.append(command)
            return mock.Mock(returncode=0)

        with (
            mock.patch("vpnctl.agent.load_state", return_value=original),
            mock.patch("vpnctl.agent.run", side_effect=fake_run),
            mock.patch("vpnctl.agent._port_is_busy", return_value=False),
            mock.patch("vpnctl.agent._mtproxy_unit", side_effect=[AgentError("failed")]),
            mock.patch("vpnctl.agent.save_state") as save_state,
            mock.patch("vpnctl.agent.os.uname", return_value=mock.Mock(machine="x86_64")),
            self.assertRaisesRegex(AgentError, "failed"),
        ):
            action_telegram_enable({})
        self.assertEqual(save_state.call_args_list[-1].args[0], original)
        self.assertTrue(any(command[-1] == "vpnctl-mtproxy-cleanup.service" for command in commands))

    def test_xray_restart_does_not_restart_control_plane(self):
        unit = (Path(__file__).resolve().parents[1] / "systemd" / "vpnctl-agent.service").read_text()
        self.assertIn("Wants=nginx.service xray.service", unit)
        self.assertNotIn("Requires=nginx.service xray.service", unit)
        xray_unit = (Path(__file__).resolve().parents[1] / "systemd" / "xray.service").read_text()
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", xray_unit)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", xray_unit)
        mtproxy_unit = (Path(__file__).resolve().parents[1] / "systemd" / "mtproxy.service").read_text()
        self.assertNotIn("443", mtproxy_unit)
        self.assertIn("ProtectProc=invisible", mtproxy_unit)
        refresh_unit = (Path(__file__).resolve().parents[1] / "systemd" / "mtproxy-refresh.service").read_text()
        helper = (Path(__file__).resolve().parents[1] / "scripts" / "mtproxy.sh").read_text()
        self.assertIn("refresh-and-restart", refresh_unit)
        self.assertIn("cmp -s", helper)
        self.assertIn("try-restart mtproxy.service", helper)


if __name__ == "__main__":
    unittest.main()
