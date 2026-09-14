import io
import json
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock

from bip39_lab.web import LabHandler, serialize_state


class WebBoundaryTests(unittest.TestCase):
    def test_state_serializes_discrete_counters_as_exact_decimal_strings(self) -> None:
        large = 2_658_455_991_569_831_745_807_614_120_560_689_152
        state = serialize_state({
            "stats": {
                "attempts": large,
                "valid_mnemonics": 128,
                "rejected_checksum": 1920,
                "total_combinations": large,
                "remaining_combinations": large - 1,
                "seeds_derived": 128,
                "derivations": 128,
                "addresses_generated": 128,
                "comparisons": 128,
                "matches": 0,
                "in_flight": 0,
                "progress_scaled": 1,
                "rate": 49.5,
            },
            "sample": {"attempt": large, "checksum_valid": False},
            "samples": [{"attempt": large, "valid": False}],
        })
        self.assertEqual(state["stats"]["total_combinations"], str(large))
        self.assertEqual(state["stats"]["remaining_combinations"], str(large - 1))
        self.assertEqual(state["sample"]["attempt"], str(large))
        self.assertEqual(state["samples"][0]["attempt"], str(large))
        for key in ("seeds_derived", "derivations", "addresses_generated", "comparisons", "matches", "in_flight"):
            self.assertIsInstance(state["stats"][key], str)
        payload = json.dumps(state)
        self.assertIn(str(large), payload)

    def handler(self, path: str = "/api/state", **overrides: str) -> LabHandler:
        handler = object.__new__(LabHandler)
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.command = "GET"
        handler.requestline = "GET / HTTP/1.1"
        handler.wfile, handler.rfile = io.BytesIO(), io.BytesIO(b"{}")
        handler.server = SimpleNamespace(server_port=8765, token="test-token", dashboard=Mock())
        handler.headers = Message()
        headers = {"Host": "127.0.0.1:8765", "X-Lab-Token": "test-token", "Origin": "http://127.0.0.1:8765", "Content-Type": "application/json", "Content-Length": "2", **overrides}
        for name, value in headers.items():
            handler.headers[name] = value
        return handler

    def test_token_origin_host_and_cross_site_guards(self) -> None:
        for headers in (
            {"X-Lab-Token": "wrong"}, {"X-Lab-Token": "é"},
            {"Origin": "https://foreign.example"}, {"Host": "foreign.example:8765"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.subTest(headers=headers):
                handler = self.handler(**headers)
                self.assertFalse(handler._check_request(api=True, mutation=True))
                self.assertIn(b"403", handler.wfile.getvalue())
        self.assertTrue(self.handler()._check_request(api=True, mutation=True))

    def test_mutations_require_origin(self) -> None:
        handler = self.handler()
        del handler.headers["Origin"]
        self.assertFalse(handler._check_request(api=True, mutation=True))

    def test_status_response_has_no_store_and_csp(self) -> None:
        handler = self.handler()
        handler.server.dashboard.state.return_value = {"status": "idle"}
        handler.do_GET()
        result = handler.wfile.getvalue()
        self.assertIn(b"Cache-Control: no-store", result)
        self.assertIn(b"frame-ancestors 'none'", result)
        self.assertIn(b"X-Frame-Options: DENY", result)
        self.assertIn(b'"status": "idle"', result)

    def test_static_routes_do_not_expose_cookie_or_source_files(self) -> None:
        for path in ("/.lab-regtest/regtest/.cookie", "/../requirements.txt", "/bip39_lab/wallet.py", "/api/reveal"):
            with self.subTest(path=path):
                handler = self.handler(path)
                handler.do_GET()
                self.assertIn(b"404", handler.wfile.getvalue())

    def test_home_injects_only_session_token_and_loads_local_assets(self) -> None:
        handler = self.handler("/")
        handler.do_GET()
        response = handler.wfile.getvalue()
        self.assertIn(b"test-token", response)
        self.assertNotIn(b"__LAB_TOKEN__", response)
        self.assertNotIn(b"https://", response)

    def test_oversized_and_non_object_bodies_rejected(self) -> None:
        handler = self.handler(**{"Content-Length": "8193"})
        with self.assertRaises(ValueError):
            handler._read_body()
        handler = self.handler()
        handler.rfile = io.BytesIO(b"[]")
        with self.assertRaises(ValueError):
            handler._read_body()

    def test_key_reveal_requires_explicit_authenticated_post(self) -> None:
        handler = self.handler("/api/reveal")
        body = json.dumps({"job_id": "example"}).encode()
        del handler.headers["Content-Length"]
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = io.BytesIO(body)
        handler.server.dashboard.reveal.return_value = {"private_key_hex": "public-test-placeholder"}
        handler.do_POST()
        handler.server.dashboard.reveal.assert_called_once_with("example")
        self.assertIn(b"no-store", handler.wfile.getvalue())
