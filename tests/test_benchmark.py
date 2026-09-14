import unittest

from bip39_lab.benchmark import MAX_SAMPLES, SECONDS_PER_YEAR, project_search_space, run_benchmark
from bip39_lab.wallet import Network


class BenchmarkTests(unittest.TestCase):
    def test_small_real_benchmark(self) -> None:
        updates: list[tuple[int, int, float]] = []
        result = run_benchmark(3, progress=lambda done, total, elapsed: updates.append((done, total, elapsed)))
        self.assertEqual(result.samples, 3)
        self.assertGreater(result.elapsed_seconds, 0)
        self.assertGreater(result.seed_seconds, 0)
        self.assertGreater(result.derivation_seconds, 0)
        self.assertLessEqual(result.seed_seconds + result.derivation_seconds, result.elapsed_seconds)
        self.assertAlmostEqual(result.candidates_per_second * result.seconds_per_candidate, 1)
        self.assertEqual(updates[-1], (3, 3, result.elapsed_seconds))

    def test_regtest_benchmark(self) -> None:
        self.assertEqual(run_benchmark(1, network=Network.REGTEST).samples, 1)

    def test_sample_limits(self) -> None:
        for samples in (0, -1, MAX_SAMPLES + 1, True, 1.5):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                run_benchmark(samples)  # type: ignore[arg-type]

    def test_projections_use_valid_mnemonic_space_and_units(self) -> None:
        projections = project_search_space(1000)
        self.assertEqual(len(projections), 6)
        self.assertEqual([(item.entropy_bits, item.percentage) for item in projections], [(128, 1), (128, 50), (128, 100), (256, 1), (256, 50), (256, 100)])
        for item in projections:
            expected = (2**item.entropy_bits) * item.percentage / 100 / 1000
            self.assertAlmostEqual(item.seconds / expected, 1)
            self.assertAlmostEqual(item.years / (expected / SECONDS_PER_YEAR), 1)

    def test_invalid_projection_rates(self) -> None:
        for rate in (0, -1, float("inf"), float("nan")):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                project_search_space(rate)
