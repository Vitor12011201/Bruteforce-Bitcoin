import unittest
from itertools import islice
from threading import Event
from unittest.mock import patch

from bip39_lab.bruteforce import (
    SearchStats, SearchStatus, SearchTemplate, brute_force, iter_candidates, parse_template,
)
from bip39_lab.wallet import (
    WORDLIST, Network, derive_wallet, generate_mnemonic, is_valid_mnemonic,
    mnemonic_from_entropy, mnemonic_to_seed, wallet_from_seed,
)
from tests.vectors import PUBLIC_MNEMONIC, PUBLIC_REGTEST_ADDRESS, PUBLIC_TESTNET_ADDRESS


def mask(phrase: str, *positions: int) -> str:
    words = phrase.split()
    for position in positions:
        words[position] = "?"
    return " ".join(words)


class BruteForceTests(unittest.TestCase):
    def test_search_space_totals_are_exact_for_one_to_eleven_unknown_words(self) -> None:
        expected = (
            "2.048",
            "4.194.304",
            "8.589.934.592",
            "17.592.186.044.416",
            "36.028.797.018.963.968",
            "73.786.976.294.838.206.464",
            "151.115.727.451.828.646.838.272",
            "309.485.009.821.345.068.724.781.056",
            "633.825.300.114.114.700.748.351.602.688",
            "1.298.074.214.633.706.907.132.624.082.305.024",
            "2.658.455.991.569.831.745.807.614.120.560.689.152",
        )
        for unknown, expected_text in enumerate(expected, start=1):
            with self.subTest(unknown=unknown):
                template = SearchTemplate(tuple(["?"] * unknown + ["abandon"] * (12 - unknown)))
                self.assertEqual(f"{template.total_combinations:,}".replace(",", "."), expected_text)

    def test_recovers_random_lab_mnemonic_one_missing_word(self) -> None:
        phrase = generate_mnemonic()
        target = derive_wallet(phrase).address
        result = brute_force(mask(phrase, 11), target)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, phrase)
        self.assertEqual(result.address, target)
        self.assertEqual(result.stats.attempts, WORDLIST.index(phrase.split()[11]) + 1)

    def test_recovers_two_words_after_carry_into_previous_position(self) -> None:
        phrase = mnemonic_from_entropy((128).to_bytes(16, "big"))
        result = brute_force(mask(phrase, 10, 11), derive_wallet(phrase).address)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, phrase)
        self.assertEqual(result.stats.total_combinations, 2048**2)
        self.assertEqual(result.stats.attempts, 2048 + WORDLIST.index(phrase.split()[11]) + 1)

    def test_recovers_nonadjacent_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 11), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)

    def test_recovers_regtest_with_passphrase(self) -> None:
        wallet = derive_wallet(PUBLIC_MNEMONIC, Network.REGTEST, "TREZOR")
        result = brute_force(mask(PUBLIC_MNEMONIC, 11), wallet.address, network=Network.REGTEST, passphrase="TREZOR")
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.address, wallet.address)

    def test_different_target_exhausts_space_without_false_positive(self) -> None:
        outside_phrase = mnemonic_from_entropy((2**127 + 1).to_bytes(16, "big"))
        result = brute_force(mask(PUBLIC_MNEMONIC, 11), derive_wallet(outside_phrase).address)
        self.assertEqual(result.status, SearchStatus.EXHAUSTED)
        self.assertIsNone(result.mnemonic)
        self.assertIsNone(result.address)
        self.assertEqual(result.stats.attempts, 2048)
        self.assertEqual(result.stats.valid_mnemonics, 128)
        self.assertEqual(result.stats.rejected_checksum, 1920)
        self.assertEqual(result.stats.seeds_derived, 128)
        self.assertEqual(result.stats.derivations, 128)
        self.assertEqual(result.stats.addresses_generated, 128)
        self.assertEqual(result.stats.comparisons, 128)
        self.assertEqual(result.stats.matches, 0)
        self.assertEqual(result.stats.in_flight, 0)
        self.assertEqual(result.stats.progress_percent, 100)
        self.assertEqual(result.stats.eta_seconds, 0)

    def test_exhaustive_one_unknown_positions_match_independent_checksum_counts(self) -> None:
        outside_phrase = mnemonic_from_entropy((2**127 + 1).to_bytes(16, "big"))
        outside_target = derive_wallet(outside_phrase).address
        for position in (0, 5, 11):
            with self.subTest(position=position):
                template = mask(PUBLIC_MNEMONIC, position)
                candidates = list(iter_candidates(parse_template(template)))
                expected_valid = sum(is_valid_mnemonic(candidate) for candidate in candidates)
                result = brute_force(template, outside_target)
                self.assertEqual(len(candidates), 2048)
                self.assertEqual(result.stats.attempts, 2048)
                self.assertEqual(result.stats.valid_mnemonics, expected_valid)
                self.assertEqual(result.stats.rejected_checksum, 2048 - expected_valid)
                self.assertEqual(result.stats.seeds_derived, expected_valid)
                self.assertEqual(result.stats.derivations, expected_valid)
                self.assertEqual(result.stats.addresses_generated, expected_valid)
                self.assertEqual(result.stats.comparisons, expected_valid)
                self.assertEqual(result.stats.matches, 0)
                self.assertEqual(result.stats.remaining_combinations, 0)
                self.assertGreaterEqual(result.stats.attempts, 0)
                self.assertGreaterEqual(result.stats.valid_mnemonics, 0)
                self.assertGreaterEqual(result.stats.rejected_checksum, 0)
                self.assertEqual(
                    result.stats.attempts,
                    result.stats.valid_mnemonics + result.stats.rejected_checksum,
                )
                self.assertLessEqual(result.stats.attempts, result.stats.total_combinations)
                self.assertGreaterEqual(result.stats.matches, 0)
                self.assertLessEqual(result.stats.matches, result.stats.comparisons)
                self.assertLessEqual(result.stats.comparisons, result.stats.valid_mnemonics)
                self.assertGreaterEqual(result.stats.progress_percent, 0)
                self.assertLessEqual(result.stats.progress_percent, 100)

    def test_checksum_rejected_before_derivation_and_stops_on_exact_match(self) -> None:
        with patch("bip39_lab.bruteforce.mnemonic_to_seed", wraps=mnemonic_to_seed) as seed, \
             patch("bip39_lab.bruteforce.wallet_from_seed", wraps=wallet_from_seed) as derive:
            result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.stats.attempts, 4)
        self.assertEqual(result.stats.rejected_checksum, 3)
        self.assertEqual(result.stats.valid_mnemonics, 1)
        self.assertEqual(result.stats.seeds_derived, 1)
        self.assertEqual(result.stats.derivations, 1)
        self.assertEqual(result.stats.addresses_generated, 1)
        self.assertEqual(result.stats.comparisons, 1)
        self.assertEqual(result.stats.matches, 1)
        seed.assert_called_once_with(PUBLIC_MNEMONIC, "")
        derive.assert_called_once()
        self.assertEqual(derive.call_args.args[1], Network.TESTNET)
        self.assertEqual(len(derive.call_args.args[0]), 64)

    def test_candidates_preserve_known_words_and_official_order(self) -> None:
        search = parse_template(mask(PUBLIC_MNEMONIC, 0, 5))
        candidates = list(islice(iter_candidates(search), 2049))
        self.assertEqual(candidates[0].split()[0], WORDLIST[0])
        self.assertEqual(candidates[1].split()[5], WORDLIST[1])
        self.assertEqual(candidates[2048].split()[0], WORDLIST[1])
        self.assertEqual(candidates[2048].split()[5], WORDLIST[0])
        for candidate in (candidates[0], candidates[1], candidates[-1]):
            for index, word in enumerate(search.words):
                if word != "?":
                    self.assertEqual(candidate.split()[index], word)

    def test_four_unknown_positions_are_allowed_with_bounded_space(self) -> None:
        search = parse_template(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3))
        self.assertEqual(len(search.unknown_positions), 4)
        self.assertEqual(search.total_combinations, 2048**4)

    def test_brute_force_searches_four_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**4)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_five_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**5)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_six_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**6)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_seven_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**7)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_eight_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6, 7), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**8)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_nine_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6, 7, 8), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**9)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_ten_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**10)
        self.assertEqual(result.stats.attempts, 1)

    def test_brute_force_searches_eleven_unknown_positions(self) -> None:
        result = brute_force(mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.FOUND)
        self.assertEqual(result.mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(result.stats.total_combinations, 2048**11)
        self.assertEqual(result.stats.attempts, 1)

    def test_invalid_template_and_excess_unknowns_rejected(self) -> None:
        for template in (
            "", "? " * 12, PUBLIC_MNEMONIC,
            mask(PUBLIC_MNEMONIC, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11), "invalid " + "abandon " * 10 + "?",
        ):
            with self.subTest(template=template), self.assertRaises(ValueError):
                parse_template(template)
        with self.assertRaises(ValueError):
            SearchTemplate(tuple(["?"] * 12))

    def test_invalid_target_rejected_before_derivation(self) -> None:
        with patch("bip39_lab.bruteforce.mnemonic_to_seed") as seed, patch("bip39_lab.bruteforce.wallet_from_seed") as derive:
            with self.assertRaises(ValueError):
                brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_REGTEST_ADDRESS)
            seed.assert_not_called()
            derive.assert_not_called()

    def test_derivation_error_returns_only_completed_attempts_and_marks_in_flight(self) -> None:
        with patch("bip39_lab.bruteforce.wallet_from_seed", side_effect=ValueError("fixture derivation error")):
            result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.ERROR)
        self.assertEqual(result.error, "fixture derivation error")
        self.assertEqual(result.stats.attempts, 3)
        self.assertEqual(result.stats.valid_mnemonics, 1)
        self.assertEqual(result.stats.rejected_checksum, 3)
        self.assertEqual(result.stats.seeds_derived, 1)
        self.assertEqual(result.stats.derivations, 0)
        self.assertEqual(result.stats.addresses_generated, 0)
        self.assertEqual(result.stats.comparisons, 0)
        self.assertEqual(result.stats.matches, 0)
        self.assertEqual(result.stats.in_flight, 1)

    def test_invalid_update_interval(self) -> None:
        for interval in (0, -1, 0.01, float("nan"), float("inf")):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, update_interval=interval)

    def test_initial_and_final_progress_without_per_attempt_output(self) -> None:
        updates: list[SearchStats] = []
        result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, progress=updates.append, update_interval=3600)
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[0].attempts, 0)
        self.assertEqual(updates[-1], result.stats)

    def test_periodic_progress_is_emitted(self) -> None:
        ticks = iter(index * 0.2 for index in range(100))
        updates: list[SearchStats] = []
        with patch("bip39_lab.bruteforce.perf_counter", side_effect=lambda: next(ticks)):
            brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, progress=updates.append, update_interval=0.1)
        self.assertTrue(any(0 < stats.attempts < 4 for stats in updates))

    def test_interruption_returns_no_match_and_consistent_counts(self) -> None:
        with patch("bip39_lab.bruteforce.wallet_from_seed", side_effect=KeyboardInterrupt):
            result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(result.status, SearchStatus.INTERRUPTED)
        self.assertIsNone(result.mnemonic)
        self.assertEqual(result.stats.attempts, 3)
        self.assertEqual(result.stats.valid_mnemonics, 1)
        self.assertEqual(result.stats.rejected_checksum, 3)
        self.assertEqual(result.stats.seeds_derived, 1)
        self.assertEqual(result.stats.derivations, 0)
        self.assertEqual(result.stats.addresses_generated, 0)
        self.assertEqual(result.stats.comparisons, 0)
        self.assertEqual(result.stats.matches, 0)
        self.assertEqual(result.stats.in_flight, 1)

    def test_statistics_units(self) -> None:
        stats = SearchStats(1024, 64, 960, 2.0, 2048)
        self.assertEqual(stats.candidates_per_second, 512)
        self.assertEqual(stats.valid_per_second, 32)
        self.assertEqual(stats.progress_percent, 50)
        self.assertEqual(stats.eta_seconds, 2)
        initial = SearchStats(0, 0, 0, 0, 2048)
        self.assertIsNone(initial.eta_seconds)
        self.assertEqual(initial.candidates_per_second, 0)

    def test_large_statistics_keep_counts_exact_for_progress_and_eta(self) -> None:
        total = 2048**8
        attempts = 9_007_199_254_740_992
        stats = SearchStats(attempts, 1, attempts - 1, 2.0, total)
        self.assertGreater(stats.attempts, 2**53 - 1)
        self.assertEqual(stats.remaining_combinations, total - attempts)
        self.assertEqual(stats.progress_scaled, attempts * 1_000_000 // total)
        self.assertEqual(stats.progress_percent, stats.progress_scaled / 10_000)
        self.assertTrue(stats.eta_seconds > 0)

    def test_result_and_template_repr_hide_mnemonic(self) -> None:
        template = mask(PUBLIC_MNEMONIC, 11)
        self.assertNotIn("abandon", repr(parse_template(template)))
        self.assertNotIn(PUBLIC_MNEMONIC, repr(brute_force(template, PUBLIC_TESTNET_ADDRESS)))

    def test_pre_cancelled_search_performs_no_attempts(self) -> None:
        cancel = Event()
        cancel.set()
        result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, cancel=cancel)
        self.assertEqual(result.status, SearchStatus.INTERRUPTED)
        self.assertEqual(result.stats.attempts, 0)

    def test_final_sample_is_actual_completed_candidate(self) -> None:
        samples = []
        result = brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, on_sample=samples.append)
        self.assertEqual(samples[-1].mnemonic, PUBLIC_MNEMONIC)
        self.assertEqual(samples[-1].attempt, result.stats.attempts)
        self.assertTrue(samples[-1].checksum_valid)
        self.assertEqual(samples[-1].last_derived_address, PUBLIC_TESTNET_ADDRESS)
        self.assertNotIn(PUBLIC_MNEMONIC, repr(samples[-1]))

    def test_invalid_final_sample_has_no_address_from_previous_candidate(self) -> None:
        samples = []
        outside_phrase = mnemonic_from_entropy((2**127).to_bytes(16, "big"))
        result = brute_force(
            mask(PUBLIC_MNEMONIC, 11), derive_wallet(outside_phrase).address,
            on_sample=samples.append,
        )
        self.assertEqual(result.status, SearchStatus.EXHAUSTED)
        self.assertFalse(samples[-1].checksum_valid)
        self.assertIsNone(samples[-1].last_derived_address)

    def test_visual_delay_limits(self) -> None:
        for delay in (-1, 0.11, float("inf"), float("nan")):
            with self.subTest(delay=delay), self.assertRaises(ValueError):
                brute_force(mask(PUBLIC_MNEMONIC, 11), PUBLIC_TESTNET_ADDRESS, visual_delay=delay)
