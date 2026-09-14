import json
import unittest
from threading import Event
from time import monotonic
from unittest.mock import patch

from bip39_lab.balance import BalanceUnavailable, TargetBalance
from bip39_lab.dashboard import Dashboard
from bip39_lab.wallet import Network, derive_wallet, mnemonic_from_entropy
from tests.test_bruteforce import mask
from tests.vectors import PUBLIC_MNEMONIC, PUBLIC_REGTEST_ADDRESS, PUBLIC_TESTNET_ADDRESS


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dashboard = Dashboard()
        self.addCleanup(self.dashboard.clear)

    def wait_for(self, predicate) -> dict:
        deadline = monotonic() + 3
        while monotonic() < deadline:
            state = self.dashboard.state()
            if predicate(state):
                return state
            Event().wait(0.005)
        self.fail("O estado esperado não foi alcançado.")

    def test_generation_returns_valid_regtest_target_without_private_key(self) -> None:
        generated = self.dashboard.generate("known-test-passphrase")
        self.assertEqual(derive_wallet(generated["mnemonic"], Network.REGTEST, "known-test-passphrase").address, generated["target"])
        self.assertEqual(generated["template"].count("?"), 1)
        self.assertNotIn("private_key", generated)

    def test_example_is_public_deterministic_and_last_word_takes_time(self) -> None:
        first, second = self.dashboard.generate(example=True), self.dashboard.generate(example=True)
        self.assertEqual(first, second)
        self.assertTrue(first["mnemonic"].endswith("wrap"))

    def test_complete_mnemonic_validation_derives_only_one_candidate(self) -> None:
        job_id = self.dashboard.start(
            PUBLIC_REGTEST_ADDRESS,
            PUBLIC_MNEMONIC,
            mode="fast",
            operation="validate",
        )
        state = self.wait_for(lambda value: value["status"] == "found")
        self.assertEqual(state["operation"], "validate")
        self.assertEqual(state["stats"]["total_combinations"], 1)
        self.assertEqual(state["stats"]["attempts"], 1)
        self.assertEqual(state["stats"]["valid_mnemonics"], 1)
        self.assertEqual(state["stats"]["seeds_derived"], 1)
        self.assertEqual(state["stats"]["derivations"], 1)
        self.assertEqual(state["stats"]["addresses_generated"], 1)
        self.assertEqual(state["stats"]["comparisons"], 1)
        self.assertEqual(state["stats"]["matches"], 1)
        self.assertEqual(state["stats"]["in_flight"], 0)
        self.assertTrue(state["can_reveal"])
        self.assertEqual(self.dashboard.reveal(job_id)["address"], PUBLIC_REGTEST_ADDRESS)

    def test_found_search_reuses_wallet_without_a_second_derivation(self) -> None:
        with patch("bip39_lab.dashboard.derive_wallet") as derive:
            job_id = self.dashboard.start(
                PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="fast"
            )
            state = self.wait_for(lambda value: value["status"] == "found")
            self.assertEqual(state["stats"]["derivations"], 1)
            self.assertEqual(self.dashboard.reveal(job_id)["address"], PUBLIC_REGTEST_ADDRESS)
            derive.assert_not_called()

    def test_derivation_error_exposes_partial_stage_without_overcounting_attempts(self) -> None:
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=BalanceUnavailable("Sem nó.")), \
             patch("bip39_lab.bruteforce.wallet_from_seed", side_effect=ValueError("fixture error")):
            self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="fast")
            state = self.wait_for(lambda value: value["status"] == "error")
        stats = state["stats"]
        self.assertEqual(state["error"], "fixture error")
        self.assertEqual(stats["attempts"], 3)
        self.assertEqual(stats["valid_mnemonics"], 1)
        self.assertEqual(stats["rejected_checksum"], 3)
        self.assertEqual(stats["seeds_derived"], 1)
        self.assertEqual(stats["derivations"], 0)
        self.assertEqual(stats["comparisons"], 0)
        self.assertEqual(stats["in_flight"], 1)

    def test_complete_mnemonic_validation_never_returns_false_positive(self) -> None:
        other = derive_wallet(mnemonic_from_entropy((2**127).to_bytes(16, "big")), Network.REGTEST)
        self.dashboard.start(other.address, PUBLIC_MNEMONIC, mode="fast", operation="validate")
        state = self.wait_for(lambda value: value["status"] == "exhausted")
        self.assertEqual(state["stats"]["total_combinations"], 1)
        self.assertEqual(state["stats"]["attempts"], 1)
        self.assertEqual(state["stats"]["valid_mnemonics"], 1)
        self.assertEqual(state["stats"]["seeds_derived"], 1)
        self.assertEqual(state["stats"]["derivations"], 1)
        self.assertEqual(state["stats"]["addresses_generated"], 1)
        self.assertEqual(state["stats"]["comparisons"], 1)
        self.assertEqual(state["stats"]["matches"], 0)
        self.assertFalse(state["can_reveal"])

    def test_funded_alert_requires_match_and_post_match_balance(self) -> None:
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=lambda: TargetBalance(100_000_000, 123, "ab" * 32, monotonic())):
            job_id = self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="fast")
            state = self.wait_for(lambda value: value.get("funded_alert"))
            self.assertEqual(state["status"], "found")
            self.assertTrue(state["balance"]["after_match"])
            self.assertNotIn("private_key", json.dumps(state))
            secret = self.dashboard.reveal(job_id)
            expected = derive_wallet(PUBLIC_MNEMONIC, Network.REGTEST)
            self.assertEqual(secret["private_key_hex"], expected.private_key.hex())
            self.assertEqual(secret["address"], PUBLIC_REGTEST_ADDRESS)
            self.assertEqual(secret["mnemonic"], PUBLIC_MNEMONIC)
            self.dashboard.clear()

    def test_positive_balance_without_match_does_not_alert_or_reveal(self) -> None:
        other = derive_wallet(mnemonic_from_entropy((2**127).to_bytes(16, "big")), Network.REGTEST)
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=lambda: TargetBalance(100_000_000, 123, "ab" * 32, monotonic())):
            job_id = self.dashboard.start(other.address, mask(PUBLIC_MNEMONIC, 11), mode="fast")
            state = self.wait_for(lambda value: value["status"] == "exhausted")
            self.assertFalse(state["funded_alert"])
            self.assertFalse(state["can_reveal"])
            with self.assertRaises(ValueError):
                self.dashboard.reveal(job_id)
            self.dashboard.clear()

    def test_unknown_and_stale_balance_never_alert(self) -> None:
        for response in (BalanceUnavailable("Sem nó."), TargetBalance(100_000_000, 123, "ab" * 32, monotonic() - 60)):
            with self.subTest(response=type(response).__name__), patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=lambda: self.balance_response(response)):
                self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="fast")
                state = self.wait_for(lambda value: value["status"] == "found")
                self.assertFalse(state["funded_alert"])
                self.assertIsNone(state["balance"]["satoshis"])
                self.dashboard.clear()

    @staticmethod
    def balance_response(value):
        if isinstance(value, Exception):
            raise value
        return value

    def test_zero_balance_matches_without_funded_alert(self) -> None:
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=lambda: TargetBalance(0, 0, "ab" * 32, monotonic())):
            self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="fast")
            state = self.wait_for(lambda value: value["status"] == "found")
            self.assertTrue(state["can_reveal"])
            self.assertFalse(state["funded_alert"])
            self.dashboard.clear()

    def test_cancel_prevents_parallel_jobs_and_clear_invalidates_reveal(self) -> None:
        generated = self.dashboard.generate(example=True)
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch", side_effect=BalanceUnavailable("Sem nó.")):
            job_id = self.dashboard.start(generated["target"], generated["template"])
            with self.assertRaises(ValueError):
                self.dashboard.start(generated["target"], generated["template"])
            with self.assertRaises(ValueError):
                self.dashboard.reveal(job_id)
            self.dashboard.stop(job_id)
            state = self.wait_for(lambda value: value["status"] == "interrupted")
            self.assertLess(state["stats"]["attempts"], 2048)
            self.dashboard.clear()
        self.assertEqual(self.dashboard.state()["status"], "idle")
        with self.assertRaises(ValueError):
            self.dashboard.reveal(job_id)

    def test_mainnet_testnet_and_unrestricted_templates_rejected_before_rpc(self) -> None:
        with patch("bip39_lab.dashboard.RegtestBalanceClient.fetch") as fetch:
            with self.assertRaises(ValueError):
                self.dashboard.start(PUBLIC_TESTNET_ADDRESS, mask(PUBLIC_MNEMONIC, 11))
            with self.assertRaises(ValueError):
                self.dashboard.start(PUBLIC_REGTEST_ADDRESS, "? " * 12)
            fetch.assert_not_called()

    def test_invalid_mode_and_rpc_configuration_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), mode="invalid")
        with self.assertRaises(ValueError):
            Dashboard(rpc_port=0)

    def test_complete_validation_rejects_incomplete_or_unknown_phrase(self) -> None:
        with self.assertRaises(ValueError):
            self.dashboard.start(PUBLIC_REGTEST_ADDRESS, "abandon " * 11, operation="validate")
        with self.assertRaises(ValueError):
            self.dashboard.start(PUBLIC_REGTEST_ADDRESS, mask(PUBLIC_MNEMONIC, 11), operation="validate")
