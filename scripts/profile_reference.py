"""Profile the bounded, serial reference pipeline with public fixtures only.

This diagnostic is intentionally separate from the normal CLI.  It does not
enumerate a search space, connect to a node, or use user-provided mnemonics.
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import pstats
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from time import perf_counter

# ``python scripts/profile_reference.py`` puts scripts/ first on sys.path.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bip39_lab.wallet import Network, is_valid_mnemonic, mnemonic_from_entropy, mnemonic_to_seed, wallet_from_seed


DEFAULT_SAMPLES = 64
MAX_SAMPLES = 256
PROFILED_SAMPLES = 16


@dataclass(frozen=True)
class StageMeasurement:
    """A non-overlapping wall-clock stage from the serial reference path."""

    name: str
    seconds: float


@dataclass(frozen=True)
class FunctionMeasurement:
    """cProfile timing for one nested function (exclusive and inclusive)."""

    name: str
    calls: int
    exclusive_seconds: float
    inclusive_seconds: float


@dataclass(frozen=True)
class ReferenceProfile:
    samples: int
    fixture_seconds: float
    elapsed_seconds: float
    stages: tuple[StageMeasurement, ...]
    pbkdf2_probe_seconds: float
    function_measurements: tuple[FunctionMeasurement, ...]

    @property
    def candidates_per_second(self) -> float:
        return self.samples / self.elapsed_seconds

    @property
    def seconds_per_candidate(self) -> float:
        return self.elapsed_seconds / self.samples


def _public_fixture_words(samples: int) -> tuple[tuple[str, ...], ...]:
    """Build deterministic public 12-word fixtures; this is measured separately."""
    return tuple(
        tuple(
            mnemonic_from_entropy(
                sha256(b"bip39-bruteforce-lab/public-reference-profile/" + index.to_bytes(4, "big")).digest()[:16]
            ).split()
        )
        for index in range(samples)
    )


def _reference_candidate(words: tuple[str, ...], target_address: str, network: Network) -> bool:
    """The existing serial order: assemble, validate, seed, wallet, compare."""
    candidate = " ".join(words)
    if not is_valid_mnemonic(candidate):  # Fixtures are valid; retain the real guard.
        raise AssertionError("A fixture pública determinística deveria ter checksum válido.")
    wallet = wallet_from_seed(mnemonic_to_seed(candidate), network)
    return wallet.address == target_address


def _cprofile_measurements(words: tuple[tuple[str, ...], ...], target_address: str, network: Network) -> tuple[FunctionMeasurement, ...]:
    """Report nested function timings without treating them as additive categories."""
    profiler = cProfile.Profile()
    profiler.enable()
    for item in words[:PROFILED_SAMPLES]:
        _reference_candidate(item, target_address, network)
    profiler.disable()

    wanted = (
        "normalize_words",
        "is_valid_mnemonic",
        "mnemonic_to_seed",
        "to_seed",
        "wallet_from_seed",
        "pbkdf2_hmac",
    )
    rows: list[FunctionMeasurement] = []
    for function, values in pstats.Stats(profiler).stats.items():
        name = function[2]
        if name not in wanted and not name.endswith("pbkdf2_hmac>"):
            continue
        primitive_calls, total_calls, exclusive, inclusive, _callers = values
        rows.append(FunctionMeasurement(name, total_calls or primitive_calls, exclusive, inclusive))
    return tuple(sorted(rows, key=lambda item: item.name))


def _direct_pbkdf2_probe(words: tuple[tuple[str, ...], ...]) -> float:
    """Time only PBKDF2 for canonical English fixtures, outside the reference API.

    This deliberately bypasses API validation and Unicode normalization.  It is
    a diagnostic lower bound for PBKDF2-HMAC-SHA512, not a replacement metric
    for ``mnemonic_to_seed`` and is never added to the pipeline total.
    """
    started = perf_counter()
    for item in words:
        phrase = " ".join(item).encode("utf-8")
        hashlib.pbkdf2_hmac("sha512", phrase, b"mnemonic", 2048)
    return perf_counter() - started


def run_profile(samples: int = DEFAULT_SAMPLES, *, network: Network = Network.TESTNET) -> ReferenceProfile:
    """Run a small reproducible serial measurement of the current reference code."""
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= MAX_SAMPLES:
        raise ValueError(f"O profiling aceita entre 1 e {MAX_SAMPLES} amostras.")
    network = Network(network)

    fixture_started = perf_counter()
    fixtures = _public_fixture_words(samples)
    fixture_seconds = perf_counter() - fixture_started

    # Warm Python/library paths outside the timed baseline.
    warm_phrase = " ".join(fixtures[0])
    warm_target = wallet_from_seed(mnemonic_to_seed(warm_phrase), network).address
    _reference_candidate(fixtures[0], warm_target, network)

    assembly = validation = seed_api = wallet = comparison = 0.0
    target_address = warm_target
    started = perf_counter()
    for words in fixtures:
        before = perf_counter()
        candidate = " ".join(words)
        after_assembly = perf_counter()
        valid = is_valid_mnemonic(candidate)
        after_validation = perf_counter()
        if not valid:
            raise AssertionError("A fixture pública determinística deveria ter checksum válido.")
        seed = mnemonic_to_seed(candidate)
        after_seed = perf_counter()
        derived = wallet_from_seed(seed, network)
        after_wallet = perf_counter()
        matched = derived.address == target_address
        after_comparison = perf_counter()

        assembly += after_assembly - before
        validation += after_validation - after_assembly
        seed_api += after_seed - after_validation
        wallet += after_wallet - after_seed
        comparison += after_comparison - after_wallet
        # The value is intentionally consumed: this is the reference comparison.
        if matched and derived.address != target_address:
            raise AssertionError("Comparação de endereço inconsistente.")
    elapsed = perf_counter() - started
    stages = (
        StageMeasurement("montagem do candidato (' '.join)", assembly),
        StageMeasurement("primeira validação BIP-39/checksum", validation),
        StageMeasurement("API mnemonic_to_seed (normalização + segunda validação + PBKDF2)", seed_api),
        StageMeasurement("wallet_from_seed (BIP-32/BIP-84 + chaves + endereço)", wallet),
        StageMeasurement("comparação de endereço", comparison),
        StageMeasurement("residual de loop/timers/orquestração", max(0.0, elapsed - assembly - validation - seed_api - wallet - comparison)),
    )
    return ReferenceProfile(
        samples,
        fixture_seconds,
        elapsed,
        stages,
        _direct_pbkdf2_probe(fixtures),
        _cprofile_measurements(fixtures, target_address, network),
    )


def _format_profile(report: ReferenceProfile) -> str:
    lines = [
        "Profiling serial da implementação de referência (fixtures públicas; sem busca/RPC):",
        f"Amostras: {report.samples}",
        f"Preparação das fixtures (fora do baseline): {report.fixture_seconds:.6f} s",
        f"Duração total do pipeline: {report.elapsed_seconds:.6f} s",
        f"Candidatos válidos/s: {report.candidates_per_second:.2f}",
        f"Custo médio por candidato válido: {report.seconds_per_candidate * 1_000:.6f} ms",
        "Etapas de parede não sobrepostas (somam aproximadamente o total):",
    ]
    lines.extend(f"  - {stage.name}: {stage.seconds:.6f} s" for stage in report.stages)
    lines.extend(
        (
            f"Sonda PBKDF2 isolada (não somar ao total): {report.pbkdf2_probe_seconds:.6f} s",
            "cProfile por função: exclusivo = corpo próprio; inclusivo = corpo + chamadas filhas.",
            "Tempos inclusivos de funções aninhadas não são categorias aditivas.",
        )
    )
    lines.extend(
        f"  - {item.name}: chamadas={item.calls}; exclusivo={item.exclusive_seconds:.6f} s; inclusivo={item.inclusive_seconds:.6f} s"
        for item in report.function_measurements
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES, help=f"1 a {MAX_SAMPLES}; padrão: {DEFAULT_SAMPLES}")
    parser.add_argument("--network", choices=[item.value for item in Network], default=Network.TESTNET.value)
    args = parser.parse_args()
    print(_format_profile(run_profile(args.samples, network=Network(args.network))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
