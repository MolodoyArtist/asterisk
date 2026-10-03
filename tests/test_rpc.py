import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpnctl.rpc import RPCError, call


class RPCTests(unittest.TestCase):
    def connection(self):
        socket_factory = mock.patch("vpnctl.rpc.socket.socket")
        mocked_socket = socket_factory.start()
        self.addCleanup(socket_factory.stop)
        connection = mocked_socket.return_value.__enter__.return_value
        return connection

    def test_connect_failure_becomes_rpc_error(self):
        connection = self.connection()
        connection.connect.side_effect = FileNotFoundError("missing socket")
        with self.assertRaisesRegex(RPCError, "temporarily unavailable"):
            call("status")

    def test_non_object_response_is_rejected(self):
        connection = self.connection()
        connection.recv.return_value = b"[]\n"
        with self.assertRaisesRegex(RPCError, "invalid response"):
            call("status")

    def test_missing_result_is_rejected(self):
        connection = self.connection()
        connection.recv.return_value = b'{"ok":true}\n'
        with self.assertRaisesRegex(RPCError, "invalid response"):
            call("status")

    def test_error_response_is_preserved(self):
        connection = self.connection()
        connection.recv.return_value = b'{"ok":false,"error":"bad request"}\n'
        with self.assertRaisesRegex(RPCError, "bad request"):
            call("status")

    def test_empty_response_is_rejected(self):
        connection = self.connection()
        connection.recv.return_value = b""
        with self.assertRaisesRegex(RPCError, "invalid response"):
            call("status")

    def test_oversized_response_is_rejected(self):
        connection = self.connection()
        connection.recv.return_value = b"x" * 65536
        with self.assertRaisesRegex(RPCError, "too large"):
            call("status")


if __name__ == "__main__":
    unittest.main()
