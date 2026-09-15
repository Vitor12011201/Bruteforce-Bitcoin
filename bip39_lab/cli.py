"""Portuguese CLI with optional fixed-target balance monitoring on local regtest."""

import argparse
import getpass
import sys
import warnings
from collections.abc import Sequence
from contextlib import nullcontext
from math import isfinite
from pathlib import Path

from bip39_lab.balance import (
    DEFAULT_COOKIE_FILE, DEFAULT_RPC_PORT, RegtestBalanceClient, TargetBalanceMonitor,
)
from bip39_lab.benchmark import DEFAULT_SAMPLES, MAX_SAMPLES, project_search_space, run_benchmark
from bip39_lab.bruteforce import SearchStats, SearchStatus, brute_force, parse_template
from bip39_lab.wallet import (
    DERIVATION_PATH,
    Network,
    derive_wallet,
    generate_mnemonic,
    validate_target_address,
)


LAB_WARNING = (
    "SOMENTE LABORATÓRIO — use apenas um alvo controlado por você.\n"
    "NUNCA envie dinheiro real nem reutilize esta mnemonic em uma carteira real.\n"
    "Busca local; saldo opcional apenas do alvo em regtest. Sem transações ou exportação de chaves."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bip39-bruteforce-lab",
        description="Laboratório BIP-39 de 12 palavras; testnet/regtest, um único alvo.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("generate", "Gerar um alvo de laboratório com 128 bits aleatórios."),
        ("brute-force", "Testar um modelo com somente 1 a 11 palavras desconhecidas."),
        ("benchmark", "Medir derivações e projetar espaços completos matematicamente."),
    ):
        command = commands.add_parser(name, help=help_text, allow_abbrev=False)
        command.add_argument("--network", choices=[item.value for item in Network], default="testnet")
        if name != "benchmark":
            command.add_argument(
                "--passphrase", action="store_true",
                help="Solicitar passphrase BIP-39 sem eco; padrão: vazia. Não é uma busca de passphrases.",
            )
        if name == "brute-force":
            command.add_argument("--target-address", help="Um único endereço P2WPKH controlado por você.")
            command.add_argument("--template", help="12 palavras entre aspas; use ? em 1 a 11 posições.")
            command.add_argument(
                "--update-interval", type=float, default=1.0,
                help="Intervalo em segundos (mínimo 0.1).",
            )
            command.add_argument(
                "--watch-target-balance", action="store_true",
                help="Mostrar saldo do alvo único via nó Bitcoin Core local; exige --network regtest.",
            )
            command.add_argument(
                "--rpc-cookie-file", type=Path, default=DEFAULT_COOKIE_FILE,
                help="Arquivo de autenticação do nó local; nunca recebe mnemonic ou chave privada.",
            )
            command.add_argument(
                "--rpc-port", type=int, default=DEFAULT_RPC_PORT,
                help="Porta RPC local (127.0.0.1); padrão: 18443.",
            )
        if name == "benchmark":
            command.add_argument(
                "--samples", type=int, default=DEFAULT_SAMPLES,
                help=f"De 1 a {MAX_SAMPLES:,}; padrão {DEFAULT_SAMPLES:,}.",
            )
    web = commands.add_parser("web", help="Abrir o painel local ao vivo, somente regtest.", allow_abbrev=False)
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--start-regtest", action="store_true", help="Iniciar o nó regtest isolado se necessário.")
    web.add_argument("--rpc-cookie-file", type=Path, default=DEFAULT_COOKIE_FILE)
    web.add_argument("--rpc-port", type=int, default=DEFAULT_RPC_PORT)
    return parser


def read_hidden(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise ValueError("Entrada sem eco indisponível. Execute em um terminal interativo.") from None


def read_passphrase(enabled: bool, *, confirm: bool = False) -> str:
    if not enabled:
        return ""
    passphrase = read_hidden("Passphrase BIP-39 (sem eco): ")
    if confirm and passphrase != read_hidden("Repita a passphrase: "):
        raise ValueError("As passphrases não coincidem.")
    return passphrase


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "calculando"
    if seconds < 60:
        return f"{seconds:.2f}s"
    if seconds < 3600:
        return f"{seconds / 60:.2f}min"
    if seconds < 86400:
        return f"{seconds / 3600:.2f}h"
    return f"{seconds / 86400:.2f}dias"


def print_progress(stats: SearchStats) -> None:
    print(
        f"Attempts: {stats.attempts:,} | Valid mnemonics: {stats.valid_mnemonics:,} | "
        f"Checksum rejected: {stats.rejected_checksum:,} | "
        f"Rate: {stats.candidates_per_second:,.2f} candidates/s | "
        f"Checksum-valid: {stats.valid_per_second:,.2f}/s | "
        f"Elapsed: {format_duration(stats.elapsed_seconds)} | "
        f"Total: {stats.total_combinations:,} | Progress: {stats.progress_percent:.4f}% | "
        f"ETA (espaço completo): {format_duration(stats.eta_seconds)}",
        file=sys.stderr, flush=True,
    )


def generate_command(args: argparse.Namespace) -> int:
    passphrase = read_passphrase(args.passphrase, confirm=True)
    phrase = generate_mnemonic()
    wallet = derive_wallet(phrase, Network(args.network), passphrase)
    print(f"Mnemonic de LABORATÓRIO: {phrase}")
    print(f"Endereço-alvo: {wallet.address}")
    print(f"Derivation path: {wallet.derivation_path}")
    print(f"Network: {wallet.network.value}")
    print(f"Passphrase: {'fornecida (não exibida)' if args.passphrase else 'vazia'}")
    print("Mnemonic exibida somente no terminal; o programa não a salva em arquivo.")
    return 0


def brute_force_command(args: argparse.Namespace) -> int:
    network = Network(args.network)
    if args.watch_target_balance and network != Network.REGTEST:
        raise ValueError("O monitor de saldo exige --network regtest e um nó Bitcoin Core local.")
    if not isfinite(args.update_interval) or args.update_interval < 0.1:
        raise ValueError("O intervalo de atualização deve ser finito e de pelo menos 0.1 s.")
    target = args.target_address
    if target is None:
        target = input("Endereço-alvo controlado por você: ").strip()
    validate_target_address(target, network)
    template = args.template
    if template is None:
        template = read_hidden("12 palavras, com 1 a 11 ? (sem eco): ")
    parsed = parse_template(template)
    passphrase = read_passphrase(args.passphrase)
    print(f"Network: {network.value} | Derivation path: {DERIVATION_PATH}", flush=True)
    print(f"Alvo único: {target}", flush=True)
    unknown = len(parsed.unknown_positions)
    print(f"Espaço limitado: 2048^{unknown} = {parsed.total_combinations:,} combinações.", flush=True)
    print("Filtro de checksum antes da derivação; em média, 1/16 passa. Ctrl+C interrompe.", flush=True)
    monitor = None
    if args.watch_target_balance:
        monitor = TargetBalanceMonitor(
            RegtestBalanceClient(target, cookie_file=args.rpc_cookie_file, port=args.rpc_port)
        )
        print("Monitor: somente o ALVO, em 127.0.0.1; leitura inicial e atualização a cada 5s.", flush=True)

    def show_progress(stats: SearchStats) -> None:
        print_progress(stats)
        if monitor is not None:
            print(monitor.status_line(), file=sys.stderr, flush=True)

    with monitor if monitor is not None else nullcontext():
        result = brute_force(
            template, target, network=network, passphrase=passphrase,
            progress=show_progress, update_interval=args.update_interval,
        )
    if result.status == SearchStatus.FOUND:
        print("ALVO EXATO ENCONTRADO — somente laboratório.")
        print(f"Mnemonic encontrada: {result.mnemonic}")
        print(f"Endereço derivado: {result.address}")
        print(f"Tentativas: {result.stats.attempts:,}")
        print(f"Tempo total: {result.stats.elapsed_seconds:.6f}s")
        return 0
    if result.status == SearchStatus.INTERRUPTED:
        print("Busca interrompida pelo usuário; nenhum resultado encontrado ou salvo.")
        return 130
    if result.status == SearchStatus.ERROR:
        print(f"Busca interrompida por erro: {result.error or 'erro desconhecido'}")
        return 2
    print("Espaço esgotado: nenhuma mnemonic candidata produziu o endereço-alvo.")
    return 1


def benchmark_progress(completed: int, total: int, elapsed: float) -> None:
    print(f"Benchmark: {completed:,}/{total:,} derivações | {elapsed:.2f}s", file=sys.stderr, flush=True)


def benchmark_command(args: argparse.Namespace) -> int:
    result = run_benchmark(args.samples, network=Network(args.network), progress=benchmark_progress)
    print(f"Network: {args.network} | Derivation path: {DERIVATION_PATH}")
    print(f"Derivações válidas: {result.samples:,} | Tempo total: {result.elapsed_seconds:.6f}s")
    print(f"Candidates/s (mnemonics válidas derivadas): {result.candidates_per_second:,.2f}")
    print(
        f"Tempo médio por candidato: {result.seconds_per_candidate:.9f}s "
        f"({result.seconds_per_candidate * 1000:.3f}ms)"
    )
    print(
        f"mnemonic_to_seed (validação + PBKDF2): {result.seed_seconds:.6f}s | "
        f"BIP-32/BIP-84 + chaves/endereço: {result.derivation_seconds:.6f}s"
    )
    print("Projeção matemática: tempo = fração × 2^bits / derivações válidas por segundo.")
    print("12 palavras: 2^128 ≈ 3.4028237e38 | 24 palavras: 2^256 ≈ 1.1579209e77")
    print(f"{'Palavras':>8} {'Bits':>5} {'Espaço':>7} {'Segundos':>16} {'Anos':>16}")
    for projection in project_search_space(result.candidates_per_second):
        words = 12 if projection.entropy_bits == 128 else 24
        print(
            f"{words:>8} {projection.entropy_bits:>5} {projection.percentage:>6}% "
            f"{projection.seconds:>16.6e} {projection.years:>16.6e}"
        )
    print(
        "Projeção ilustrativa: taxa de 12 palavras, um processo, passphrase vazia e um caminho.\n"
        "Hardware e paralelização mudam a taxa, mas não tornam a enumeração completa praticável.\n"
        "24 palavras aparecem apenas no cálculo; não são geradas nem buscadas.\n"
        "Percorrer uma fração do espaço não garante encontrar um alvo nessa fração.\n"
        "Para 24 palavras, estes números descrevem enumerar mnemonics, não a segurança\n"
        "de preimagem de um endereço P2WPKH de 160 bits."
    )
    return 0


def web_command(args: argparse.Namespace) -> int:
    from bip39_lab.web import serve

    serve(args.port, start_node=args.start_regtest, cookie_file=args.rpc_cookie_file, rpc_port=args.rpc_port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(LAB_WARNING, file=sys.stderr, flush=True)
    handlers = {
        "generate": generate_command,
        "brute-force": brute_force_command,
        "benchmark": benchmark_command,
        "web": web_command,
    }
    try:
        return handlers[args.command](args)
    except (ValueError, EOFError) as error:
        message = (
            str(error) if isinstance(error, ValueError)
            else "Entrada encerrada antes de completar os dados."
        )
        print(f"Erro: {message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Operação interrompida pelo usuário.", file=sys.stderr)
        return 130
