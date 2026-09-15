import unittest

from bip39_lab.wallet import Network
from scripts.profile_reference import MAX_SAMPLES, run_profile


class ReferenceProfileTests(unittest.TestCase):
    def test_small_public_profile_reports_serial_reference_stages(self) -> None:
        report = run_profile(2, network=Network.REGTEST)
        self.assertEqual(report.samples, 2)
        self.assertGreater(report.fixture_seconds, 0)
        self.assertGreater(report.elapsed_seconds, 0)
        self.assertGreater(report.candidates_per_second, 0)
        self.assertEqual(len(report.stages), 6)
        self.assertTrue(all(stage.seconds >= 0 for stage in report.stages))
        self.assertGreater(report.pbkdf2_probe_seconds, 0)
        self.assertTrue(any(item.name == "mnemonic_to_seed" for item in report.function_measurements))

    def test_profile_sample_limit_is_bounded(self) -> None:
        for samples in (0, MAX_SAMPLES + 1, True, 1.5):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                run_profile(samples)  # type: ignore[arg-type]
