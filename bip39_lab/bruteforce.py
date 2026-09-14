"""Exhaust a small, explicitly supplied template against exactly one address."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from enum import Enum
from itertools import product
from math import isfinite
from threading import Event
from time import perf_counter

from bip39_lab.wallet import (
    WORD_SET,
    WORDLIST,
    Network,
    is_valid_mnemonic,
    mnemonic_to_seed,
    normalize_words,
    validate_target_address,
    wallet_from_seed,
    Wallet,
)


MAX_UNKNOWN_WORDS = 11


@dataclass(frozen=True)
class SearchTemplate:
    words: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.words) != 12:
            raise ValueError("O modelo deve conter exatamente 12 palavras.")
        if any(word != "?" and word not in WORD_SET for word in self.words):
            raise ValueError("As palavras conhecidas devem pertencer à wordlist BIP-39 English.")
        if not 1 <= len(self.unknown_positions) <= MAX_UNKNOWN_WORDS:
            raise ValueError("Use de 1 a 11 posições desconhecidas (?). Este limite é fixo.")

    @property
    def unknown_positions(self) -> tuple[int, ...]:
        return tuple(index for index, word in enumerate(self.words) if word == "?")

    @property
    def total_combinations(self) -> int:
        return len(WORDLIST) ** len(self.unknown_positions)


def parse_template(phrase: str) -> SearchTemplate:
    return SearchTemplate(tuple(normalize_words(phrase).split()))


def iter_candidates(template: SearchTemplate) -> Iterator[str]:
    words = list(template.words)
    positions = template.unknown_positions
    for replacement in product(WORDLIST, repeat=len(positions)):
        for position, word in zip(positions, replacement, strict=True):
            words[position] = word
        yield " ".join(words)


@dataclass(frozen=True)
class SearchStats:
    attempts: int
    valid_mnemonics: int
    rejected_checksum: int
    elapsed_seconds: float
    total_combinations: int
    seeds_derived: int = 0
    derivations: int = 0
    addresses_generated: int = 0
    comparisons: int = 0
    matches: int = 0
    in_flight: int = 0

    @property
    def candidates_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return float(Decimal(self.attempts) / Decimal(str(self.elapsed_seconds)))

    @property
    def valid_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return float(Decimal(self.valid_mnemonics) / Decimal(str(self.elapsed_seconds)))

    @property
    def remaining_combinations(self) -> int:
        return max(0, self.total_combinations - self.attempts)

    @property
    def progress_scaled(self) -> int:
        """Percentage scaled by 10,000, exact to the UI's four decimals."""
        if self.total_combinations <= 0:
            return 0
        return min(1_000_000, self.attempts * 1_000_000 // self.total_combinations)

    @property
    def progress_percent(self) -> float:
        return self.progress_scaled / 10_000

    @property
    def eta_seconds(self) -> float | None:
        remaining = self.remaining_combinations
        if remaining == 0:
            return 0.0
        rate = self.candidates_per_second
        if rate <= 0:
            return None
        # Keep the large integer exact until the final, human-readable float.
        with localcontext() as context:
            context.prec = max(28, len(str(remaining)) + 16)
            return float(Decimal(remaining) / Decimal(str(rate)))


class SearchStatus(str, Enum):
    FOUND = "found"
    EXHAUSTED = "exhausted"
    INTERRUPTED = "interrupted"
    ERROR = "error"


@dataclass(frozen=True)
class SearchResult:
    status: SearchStatus
    stats: SearchStats
    mnemonic: str | None = field(default=None, repr=False)
    address: str | None = None
    wallet: Wallet | None = field(default=None, repr=False)
    error: str | None = None


ProgressCallback = Callable[[SearchStats], None]


@dataclass(frozen=True)
class CandidateSample:
    attempt: int
    mnemonic: str = field(repr=False)
    checksum_valid: bool
    last_derived_address: str | None


def brute_force(
    template: str,
    target_address: str,
    *,
    network: Network = Network.TESTNET,
    passphrase: str = "",
    progress: ProgressCallback | None = None,
    update_interval: float = 1.0,
    cancel: Event | None = None,
    on_sample: Callable[[CandidateSample], None] | None = None,
    visual_delay: float = 0.0,
) -> SearchResult:
    network = Network(network)
    target_address = validate_target_address(target_address, network)
    search = parse_template(template)
    if not isfinite(update_interval) or update_interval < 0.1:
        raise ValueError("O intervalo de atualização deve ser finito e de pelo menos 0.1 s.")
    if not isfinite(visual_delay) or not 0 <= visual_delay <= 0.1:
        raise ValueError("A pausa visual deve ficar entre 0 e 0.1 s.")
    cancellation = cancel if cancel is not None else Event()

    attempts = valid = rejected = 0
    seeds_derived = derivations = addresses_generated = comparisons = matches = 0
    in_flight = 0
    last_candidate = ""
    checksum_valid = False
    last_address: str | None = None
    started = perf_counter()
    next_update = started + update_interval

    def snapshot() -> SearchStats:
        return SearchStats(
            attempts, valid, rejected, perf_counter() - started, search.total_combinations,
            seeds_derived, derivations, addresses_generated, comparisons, matches, in_flight,
        )

    def finish(
        status: SearchStatus, mnemonic: str | None = None, address: str | None = None,
        wallet: Wallet | None = None, error: str | None = None,
    ) -> SearchResult:
        stats = snapshot()
        if progress is not None:
            progress(stats)
        if on_sample is not None and attempts:
            on_sample(CandidateSample(attempts, last_candidate, checksum_valid, last_address))
        return SearchResult(status, stats, mnemonic, address, wallet, error)

    if progress is not None:
        progress(snapshot())
    try:
        for candidate in iter_candidates(search):
            if cancellation.is_set() or (visual_delay and cancellation.wait(visual_delay)):
                return finish(SearchStatus.INTERRUPTED)
            in_flight = 1
            candidate_valid = is_valid_mnemonic(candidate)
            if not candidate_valid:
                rejected += 1
                attempts += 1
                candidate_address = None
                candidate_wallet = None
                in_flight = 0
            else:
                valid += 1
                seed = mnemonic_to_seed(candidate, passphrase)
                seeds_derived += 1
                candidate_wallet = wallet_from_seed(seed, network)
                derivations += 1
                addresses_generated += 1
                candidate_address = candidate_wallet.address
                comparisons += 1
                if candidate_address == target_address:
                    matches += 1
                attempts += 1
                in_flight = 0
            last_candidate, checksum_valid = candidate, candidate_valid
            last_address = candidate_address
            if candidate_valid:
                if candidate_address == target_address:
                    return finish(SearchStatus.FOUND, candidate, candidate_address, candidate_wallet)
            if (progress is not None or on_sample is not None) and perf_counter() >= next_update:
                if progress is not None:
                    progress(snapshot())
                if on_sample is not None:
                    on_sample(CandidateSample(attempts, candidate, checksum_valid, candidate_address))
                next_update = perf_counter() + update_interval
    except KeyboardInterrupt:
        return finish(SearchStatus.INTERRUPTED)
    except Exception as error:
        return finish(SearchStatus.ERROR, error=str(error))
    return finish(SearchStatus.EXHAUSTED)
