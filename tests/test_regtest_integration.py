"""Opt-in read-only integration: BIP39_LAB_LIVE_REGTEST=1 python -m unittest ..."""

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from bip39_lab.balance import RegtestBalanceClient
from bip39_lab.cli import main
from tests.test_bruteforce import mask
from tests.vectors import PUBLIC_MNEMONIC, PUBLIC_REGTEST_ADDRESS


@unittest.skipUnless(os.environ.get("BIP39_LAB_LIVE_REGTEST") == "1", "Requer nó local e opt-in de integração RPC.")
class LiveRegtestTests(unittest.TestCase):
    def test_real_node_confirms_target_balance(self) -> None:
        result = RegtestBalanceClient(PUBLIC_REGTEST_ADDRESS).fetch()
        self.assertGreaterEqual(result.satoshis, 0)
        self.assertGreaterEqual(result.height, 0)

    def test_cli_queries_live_node_and_recovers_test_mnemonic(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main([
                "brute-force", "--network", "regtest", "--watch-target-balance",
                "--target-address", PUBLIC_REGTEST_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11),
            ])
        self.assertEqual(result, 0)
        self.assertIn("ALVO EXATO ENCONTRADO", stdout.getvalue())
        self.assertIn("BTC de teste (regtest)", stderr.getvalue())
        self.assertNotIn("indisponível", stderr.getvalue())
