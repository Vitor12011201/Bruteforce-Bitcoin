import io
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from time import monotonic
from unittest.mock import patch

from bip39_lab.balance import BalanceUnavailable, TargetBalance
from bip39_lab.cli import main
from bip39_lab.wallet import mnemonic_from_entropy, derive_wallet
from tests.test_bruteforce import mask
from tests.vectors import PUBLIC_MNEMONIC, PUBLIC_REGTEST_ADDRESS, PUBLIC_TESTNET_ADDRESS


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_generate_shows_warning_path_and_no_private_key(self) -> None:
        with patch("bip39_lab.cli.generate_mnemonic", return_value=PUBLIC_MNEMONIC):
            code, stdout, stderr = self.run_cli("generate")
        self.assertEqual(code, 0)
        self.assertIn("NUNCA envie dinheiro real", stderr)
        self.assertIn(PUBLIC_MNEMONIC, stdout)
        self.assertIn(PUBLIC_TESTNET_ADDRESS, stdout)
        self.assertIn("m/84'/1'/0'/0/0", stdout)
        self.assertNotIn("private_key", stdout)

    def test_successful_search_cli(self) -> None:
        code, stdout, stderr = self.run_cli("brute-force", "--target-address", PUBLIC_TESTNET_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11))
        self.assertEqual(code, 0)
        self.assertIn("ALVO EXATO ENCONTRADO", stdout)
        self.assertIn(PUBLIC_MNEMONIC, stdout)
        self.assertIn("2048^1 = 2,048", stdout)
        self.assertIn("Attempts: 4", stderr)
        self.assertNotIn(PUBLIC_MNEMONIC, stderr)

    def test_interactive_search(self) -> None:
        with patch("builtins.input", return_value=PUBLIC_TESTNET_ADDRESS), patch("bip39_lab.cli.getpass.getpass", return_value=mask(PUBLIC_MNEMONIC, 11)):
            code, stdout, _ = self.run_cli("brute-force")
        self.assertEqual(code, 0)
        self.assertIn("ALVO EXATO ENCONTRADO", stdout)

    def test_generate_passphrase_confirmation_mismatch(self) -> None:
        with patch("bip39_lab.cli.getpass.getpass", side_effect=["one", "two"]), patch("bip39_lab.cli.generate_mnemonic") as generate:
            code, _, stderr = self.run_cli("generate", "--passphrase")
        self.assertEqual(code, 2)
        self.assertIn("não coincidem", stderr)
        generate.assert_not_called()

    def test_exhausted_exit_code(self) -> None:
        phrase = mnemonic_from_entropy((2**127).to_bytes(16, "big"))
        code, stdout, _ = self.run_cli("brute-force", "--target-address", derive_wallet(phrase).address, "--template", mask(PUBLIC_MNEMONIC, 11))
        self.assertEqual(code, 1)
        self.assertIn("Espaço esgotado", stdout)
        self.assertNotIn("Mnemonic encontrada", stdout)

    def test_input_error_has_no_traceback(self) -> None:
        code, _, stderr = self.run_cli("brute-force", "--target-address", "invalid", "--template", "? " * 12)
        self.assertEqual(code, 2)
        self.assertIn("Erro:", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_mainnet_cli_option_rejected(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["generate", "--network", "mainnet"])
        self.assertEqual(error.exception.code, 2)

    def test_benchmark_shows_both_spaces_and_fractions(self) -> None:
        code, stdout, _ = self.run_cli("benchmark", "--samples", "2")
        self.assertEqual(code, 0)
        for expected in ("Candidates/s", "2^128", "2^256", "1%", "50%", "100%", "Segundos", "Anos"):
            self.assertIn(expected, stdout)
        self.assertNotIn("Mnemonic encontrada", stdout)

    def test_ctrl_c_search_exit_code(self) -> None:
        with patch("bip39_lab.bruteforce.wallet_from_seed", side_effect=KeyboardInterrupt):
            code, stdout, stderr = self.run_cli("brute-force", "--target-address", PUBLIC_TESTNET_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11))
        self.assertEqual(code, 130)
        self.assertIn("Busca interrompida", stdout)
        self.assertIn("Attempts: 3", stderr)

    def test_derivation_error_reports_only_completed_attempts(self) -> None:
        with patch("bip39_lab.bruteforce.wallet_from_seed", side_effect=ValueError("fixture error")):
            code, stdout, stderr = self.run_cli(
                "brute-force", "--target-address", PUBLIC_TESTNET_ADDRESS,
                "--template", mask(PUBLIC_MNEMONIC, 11),
            )
        self.assertEqual(code, 2)
        self.assertIn("Busca interrompida por erro", stdout)
        self.assertIn("Attempts: 3", stderr)

    def test_all_commands_work_with_network_calls_forbidden(self) -> None:
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(name, side_effect=AssertionError("Network access forbidden"))) for name in ("socket.socket.connect", "socket.socket.connect_ex", "socket.getaddrinfo")]
            stack.enter_context(patch("bip39_lab.cli.generate_mnemonic", return_value=PUBLIC_MNEMONIC))
            self.assertEqual(self.run_cli("generate")[0], 0)
            self.assertEqual(self.run_cli("brute-force", "--target-address", PUBLIC_TESTNET_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11))[0], 0)
            self.assertEqual(self.run_cli("benchmark", "--samples", "2")[0], 0)
            for guard in guards:
                guard.assert_not_called()

    def test_monitor_refuses_testnet(self) -> None:
        code, _, stderr = self.run_cli("brute-force", "--watch-target-balance")
        self.assertEqual(code, 2)
        self.assertIn("exige --network regtest", stderr)

    def test_monitored_search_finds_exact_target_with_zero_or_positive_balance(self) -> None:
        for satoshis in (0, 100_000_000):
            with self.subTest(satoshis=satoshis), patch("bip39_lab.balance.RegtestBalanceClient.fetch") as fetch:
                fetch.return_value = TargetBalance(satoshis, 123, "ab" * 32, monotonic())
                code, stdout, stderr = self.run_cli(
                    "brute-force", "--network", "regtest", "--watch-target-balance",
                    "--target-address", PUBLIC_REGTEST_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11),
                )
            self.assertEqual(code, 0)
            self.assertIn("ALVO EXATO ENCONTRADO", stdout)
            self.assertIn("Saldo do ALVO:", stderr)
            self.assertIn("BTC de teste (regtest)", stderr)
            self.assertIn("Attempts: 4", stderr)
            fetch.assert_called_once_with()

    def test_missing_node_does_not_stop_local_search(self) -> None:
        with patch("bip39_lab.balance.RegtestBalanceClient.fetch", side_effect=BalanceUnavailable("Nó indisponível.")):
            code, stdout, stderr = self.run_cli(
                "brute-force", "--network", "regtest", "--watch-target-balance",
                "--target-address", PUBLIC_REGTEST_ADDRESS, "--template", mask(PUBLIC_MNEMONIC, 11),
            )
        self.assertEqual(code, 0)
        self.assertIn("ALVO EXATO ENCONTRADO", stdout)
        self.assertIn("indisponível (não significa zero)", stderr)
        self.assertNotIn("0.00000000 BTC", stderr)
