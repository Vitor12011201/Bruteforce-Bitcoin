"""Bounded derivation benchmark and mathematical projections, without search."""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from time import perf_counter

from bip39_lab.wallet import Network, mnemonic_from_entropy, mnemonic_to_seed, wallet_from_seed


DEFAULT_SAMPLES = 1_000
MAX_SAMPLES = 10_000
SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60
BenchmarkProgress = Callable[[int, int, float], None]


@dataclass(frozen=True)
class BenchmarkResult:
    samples: int
    elapsed_seconds: float
    seed_seconds: float
    derivation_seconds: float

    @property
    def candidates_per_second(self) -> float:
        return self.samples / self.elapsed_seconds

    @property
    def seconds_per_candidate(self) -> float:
        return self.elapsed_seconds / self.samples


@dataclass(frozen=True)
class Projection:
    entropy_bits: int
    percentage: int
    seconds: float

    @property
    def years(self) -> float:
        return self.seconds / SECONDS_PER_YEAR


def project_search_space(valid_candidates_per_second: float) -> tuple[Projection, ...]:
    if not isfinite(valid_candidates_per_second) or valid_candidates_per_second <= 0:
        raise ValueError("A taxa deve ser finita e maior que zero.")
    return tuple(
        Projection(bits, percent, (2**bits) * (percent / 100) / valid_candidates_per_second)
        for bits in (128, 256)
        for percent in (1, 50, 100)
    )


def run_benchmark(
    samples: int = DEFAULT_SAMPLES,
    *,
    network: Network = Network.TESTNET,
    progress: BenchmarkProgress | None = None,
) -> BenchmarkResult:
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= MAX_SAMPLES:
        raise ValueError(f"O benchmark aceita entre 1 e {MAX_SAMPLES:,} derivações.")
    network = Network(network)
    # Public, predictable fixtures only. Setup and one warmup are excluded.
    phrases = tuple(
        mnemonic_from_entropy(
            sha256(b"bip39-bruteforce-lab/public-benchmark/" + index.to_bytes(4, "big")).digest()[:16]
        )
        for index in range(samples)
    )
    wallet_from_seed(mnemonic_to_seed(phrases[0]), network)
    seed_seconds = derivation_seconds = 0.0
    started = perf_counter()
    next_update = started + 1.0
    for completed, phrase in enumerate(phrases, start=1):
        before_seed = perf_counter()
        seed = mnemonic_to_seed(phrase)
        before_derivation = perf_counter()
        wallet_from_seed(seed, network)
        after_derivation = perf_counter()
        seed_seconds += before_derivation - before_seed
        derivation_seconds += after_derivation - before_derivation
        if progress is not None and after_derivation >= next_update:
            progress(completed, samples, after_derivation - started)
            next_update = perf_counter() + 1.0
    elapsed = perf_counter() - started
    if progress is not None:
        progress(samples, samples, elapsed)
    return BenchmarkResult(samples, elapsed, seed_seconds, derivation_seconds)
