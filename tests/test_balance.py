import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from threading import Event
from time import monotonic
from unittest.mock import MagicMock, patch

from bip39_lab.balance import (
    BalanceUnavailable, RegtestBalanceClient, TargetBalance, TargetBalanceMonitor,
)
from bip39_lab.bruteforce import SearchStatus, brute_force
from tests.test_bruteforce import mask
from tests.vectors import PUBLIC_MNEMONIC, PUBLIC_REGTEST_ADDRESS, PUBLIC_TESTNET_ADDRESS


BLOCK_HASH = "ab" * 32


def scan_result(amount: str = "0.12500001") -> dict[str, object]:
    return {"success": True, "total_amount": Decimal(amount), "height": 123, "bestblock": BLOCK_HASH}


class BalanceClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS)

    def test_only_exact_target_descriptor_is_queried(self) -> None:
        with patch.object(self.client, "_rpc", side_effect=[{"chain": "regtest"}, scan_result()]) as rpc:
            result = self.client.fetch()
        self.assertEqual(result.satoshis, 12_500_001)
        self.assertEqual(result.height, 123)
        self.assertEqual(rpc.call_args_list[0].args, ("getblockchaininfo", []))
        self.assertEqual(rpc.call_args_list[1].args, ("scantxoutset", ["start", [f"addr({PUBLIC_REGTEST_ADDRESS})"]]))

    def test_mainnet_and_testnet_nodes_rejected_before_utxo_query(self) -> None:
        for chain in ("main", "test", "testnet4", "signet", None):
            with self.subTest(chain=chain), patch.object(self.client, "_rpc", return_value={"chain": chain}) as rpc:
                with self.assertRaises(BalanceUnavailable):
                    self.client.fetch()
                rpc.assert_called_once_with("getblockchaininfo", [])

    def test_testnet_address_and_invalid_ports_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RegtestBalanceClient(PUBLIC_TESTNET_ADDRESS)
        for port in (0, 65536, -1, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS, port=port)

    def test_same_block_reuses_balance_and_changed_tip_queries_again(self) -> None:
        replies = [
            {"chain": "regtest", "bestblockhash": BLOCK_HASH}, scan_result(),
            {"chain": "regtest", "bestblockhash": BLOCK_HASH},
            {"chain": "regtest", "bestblockhash": "cd" * 32},
            {**scan_result("0"), "bestblock": "cd" * 32},
        ]
        with patch.object(self.client, "_rpc", side_effect=replies) as rpc:
            first = self.client.fetch()
            second = self.client.fetch()
            third = self.client.fetch()
        self.assertEqual(first.satoshis, second.satoshis)
        self.assertGreaterEqual(second.checked_at, first.checked_at)
        self.assertEqual(third.satoshis, 0)
        self.assertEqual(sum(call.args[0] == "scantxoutset" for call in rpc.call_args_list), 2)

    def test_malformed_or_incomplete_scan_is_not_zero(self) -> None:
        for reply in (
            {"success": False}, {}, {**scan_result(), "height": -1},
            {**scan_result(), "bestblock": "invalid"}, {**scan_result(), "height": True},
            scan_result("-1"), scan_result("NaN"), scan_result("Infinity"), scan_result("0.000000001"),
        ):
            with self.subTest(reply=reply), patch.object(self.client, "_rpc", side_effect=[{"chain": "regtest"}, reply]):
                with self.assertRaises(BalanceUnavailable):
                    self.client.fetch()

    def test_disallowed_rpc_method_never_connects(self) -> None:
        with patch("bip39_lab.balance.HTTPConnection") as connection:
            with self.assertRaises(BalanceUnavailable):
                self.client._rpc("sendtoaddress", [])
            connection.assert_not_called()

    def test_missing_cookie_does_not_connect_or_report_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS, cookie_file=Path(directory) / "missing")
            with patch("bip39_lab.balance.HTTPConnection") as connection:
                with self.assertRaises(BalanceUnavailable):
                    client.fetch()
                connection.assert_not_called()

    def test_http_uses_only_loopback_and_decimal_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cookie = Path(directory) / "test.cookie"
            cookie.write_text("public-test-user:public-test-password", encoding="utf-8")
            client = RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS, cookie_file=cookie)
            with patch("bip39_lab.balance.HTTPConnection") as connection:
                response = connection.return_value.getresponse.return_value
                response.status = 200
                response.read.return_value = b'{"id":"lab-balance","result":{"amount":0.00000001}}'
                result = client._rpc("getblockchaininfo", [])
            connection.assert_called_once_with("127.0.0.1", 18443, timeout=3.0)
            request = connection.return_value.request.call_args
            self.assertEqual(request.args, ("POST", "/"))
            payload = json.loads(request.kwargs["body"])
            self.assertEqual(payload["method"], "getblockchaininfo")
            self.assertEqual(result["amount"], Decimal("0.00000001"))
            connection.return_value.close.assert_called_once()

    def test_http_errors_and_invalid_json_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cookie = Path(directory) / "test.cookie"
            cookie.write_text("public-user:public-test-password", encoding="utf-8")
            client = RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS, cookie_file=cookie)
            for status, body in ((401, b""), (302, b""), (200, b"not-json"), (200, b"[]")):
                with self.subTest(status=status, body=body), patch("bip39_lab.balance.HTTPConnection") as connection:
                    response = connection.return_value.getresponse.return_value
                    response.status, response.read.return_value = status, body
                    with self.assertRaises(BalanceUnavailable) as error:
                        client._rpc("getblockchaininfo", [])
                    self.assertNotIn("public-test-password", str(error.exception))
                    connection.return_value.close.assert_called_once()


class BalanceMonitorTests(unittest.TestCase):
    def test_shows_eight_decimals_and_test_network(self) -> None:
        client = MagicMock(spec=RegtestBalanceClient)
        client.fetch.return_value = TargetBalance(12_500_001, 123, BLOCK_HASH, monotonic())
        with TargetBalanceMonitor(client) as monitor:
            line = monitor.status_line()
        self.assertIn("0.12500001 BTC de teste (regtest)", line)
        self.assertIn("12,500,001 sat", line)
        self.assertIn("Bloco: 123", line)

    def test_unavailable_is_never_zero_or_previous_balance(self) -> None:
        client = MagicMock(spec=RegtestBalanceClient)
        client.fetch.side_effect = [
            TargetBalance(100_000_000, 123, BLOCK_HASH, monotonic()),
            BalanceUnavailable("Nó indisponível."),
            TargetBalance(0, 124, "cd" * 32, monotonic()),
        ]
        with TargetBalanceMonitor(client) as monitor:
            self.assertIn("1.00000000", monitor.status_line())
            monitor._refresh()
            self.assertIn("indisponível (não significa zero)", monitor.status_line())
            self.assertNotIn("1.00000000", monitor.status_line())
            monitor._refresh()
            self.assertIn("0.00000000 BTC de teste", monitor.status_line())

    def test_slow_background_refresh_does_not_block_bruteforce(self) -> None:
        started, release = Event(), Event()
        snapshot = TargetBalance(0, 0, BLOCK_HASH, monotonic())
        client = MagicMock(spec=RegtestBalanceClient)

        def slow_fetch() -> TargetBalance:
            if client.fetch.call_count > 1:
                started.set()
                release.wait(timeout=2)
            return snapshot

        client.fetch.side_effect = slow_fetch
        with patch("bip39_lab.balance.POLL_INTERVAL", 0.01):
            with TargetBalanceMonitor(client) as monitor:
                try:
                    self.assertTrue(started.wait(timeout=1))
                    result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS)
                    self.assertEqual(result.status, SearchStatus.FOUND)
                    self.assertFalse(release.is_set())
                    self.assertIn("0.00000000", monitor.status_line())
                finally:
                    release.set()
            self.assertFalse(monitor._thread.is_alive())
