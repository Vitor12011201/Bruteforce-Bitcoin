"""Single-target, in-memory dashboard session. All jobs are regtest-only."""

from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from secrets import token_hex
from threading import Event, Lock, Thread
from time import monotonic
from typing import Any

from bip39_lab.balance import DEFAULT_COOKIE_FILE, DEFAULT_RPC_PORT, BalanceUnavailable, RegtestBalanceClient, TargetBalance
from bip39_lab.bruteforce import CandidateSample, SearchStats, SearchStatus, brute_force, parse_template
from bip39_lab.wallet import (
    DERIVATION_PATH,
    Network,
    Wallet,
    derive_wallet,
    generate_mnemonic,
    is_valid_mnemonic,
    mnemonic_to_seed,
    mnemonic_from_entropy,
    normalize_words,
    validate_target_address,
    wallet_from_seed,
)


@dataclass
class DashboardJob:
    target: str
    template: str = field(repr=False)
    mode: str
    operation: str = "limited"
    job_id: str = field(default_factory=lambda: token_hex(12))
    lock: Any = field(default_factory=Lock, repr=False)
    cancel: Event = field(default_factory=Event, repr=False)
    closed: Event = field(default_factory=Event, repr=False)
    refresh: Event = field(default_factory=Event, repr=False)
    status: str = "running"
    stats: SearchStats | None = None
    sample: CandidateSample | None = field(default=None, repr=False)
    samples: deque = field(default_factory=lambda: deque(maxlen=6), repr=False)
    balance: TargetBalance | None = None
    balance_error: str | None = None
    found_at: float | None = None
    mnemonic: str | None = field(default=None, repr=False)
    wallet: Wallet | None = field(default=None, repr=False)
    error: str | None = None
    worker: Thread | None = field(default=None, repr=False)


class Dashboard:
    def __init__(self, cookie_file: Path = DEFAULT_COOKIE_FILE, rpc_port: int = DEFAULT_RPC_PORT) -> None:
        if type(rpc_port) is not int or not 1 <= rpc_port <= 65535:
            raise ValueError("A porta RPC deve estar entre 1 e 65535.")
        self.cookie_file, self.rpc_port = cookie_file, rpc_port
        self._lock = Lock()
        self._job: DashboardJob | None = None

    @staticmethod
    def generate(passphrase: str = "", *, example: bool = False) -> dict[str, str]:
        phrase = mnemonic_from_entropy((127).to_bytes(16, "big")) if example else generate_mnemonic()
        wallet = derive_wallet(phrase, Network.REGTEST, passphrase)
        return {
            "mnemonic": phrase,
            "target": wallet.address,
            "template": " ".join(phrase.split()[:-1] + ["?"]),
        }

    def start(
        self,
        target: str,
        template: str,
        passphrase: str = "",
        mode: str = "visual",
        operation: str = "limited",
    ) -> str:
        validate_target_address(target, Network.REGTEST)
        if mode not in {"visual", "fast"}:
            raise ValueError("Escolha o modo visual ou sem pausa.")
        if operation not in {"limited", "validate"}:
            raise ValueError("Escolha uma operação válida.")
        if operation == "limited":
            parsed = parse_template(template)
            normalized_template = " ".join(parsed.words)
            total_combinations = parsed.total_combinations
        else:
            normalized_template = normalize_words(template)
            words = normalized_template.split()
            if len(words) != 12:
                raise ValueError("A validação direta exige exatamente 12 palavras.")
            if "?" in words:
                raise ValueError("A validação direta não usa ?. Informe as 12 palavras.")
            total_combinations = 1
        with self._lock:
            if self._job is not None and self._job.status in {"running", "stopping"}:
                raise ValueError("Já existe uma busca em andamento. Interrompa-a antes de iniciar outra.")
            self._close_current()
            job = DashboardJob(target, normalized_template, mode, operation)
            job.stats = SearchStats(0, 0, 0, 0.0, total_combinations)
            self._job = job
            Thread(target=self._balance_loop, args=(job,), name="dashboard-balance", daemon=True).start()
            job.worker = Thread(target=self._search, args=(job, passphrase), name="dashboard-search", daemon=True)
            job.worker.start()
            return job.job_id

    def _close_current(self) -> None:
        if self._job is not None:
            self._job.cancel.set()
            self._job.closed.set()
            self._job.refresh.set()
            if self._job.worker is not None:
                self._job.worker.join(timeout=0.5)

    def clear(self) -> None:
        with self._lock:
            self._close_current()
            self._job = None

    def stop(self, job_id: str) -> None:
        with self._lock:
            job = self._require_job(job_id)
            with job.lock:
                if job.status == "running":
                    job.status = "stopping"
                    job.cancel.set()

    def _require_job(self, job_id: str) -> DashboardJob:
        if self._job is None or self._job.job_id != job_id:
            raise ValueError("Este experimento não está mais ativo.")
        return self._job

    def _balance_loop(self, job: DashboardJob) -> None:
        client = RegtestBalanceClient(job.target, cookie_file=self.cookie_file, port=self.rpc_port)
        while not job.closed.is_set():
            try:
                balance = client.fetch()
            except BalanceUnavailable as error:
                with job.lock:
                    job.balance_error = str(error)
            else:
                with job.lock:
                    job.balance, job.balance_error = balance, None
            job.refresh.wait(5.0)
            job.refresh.clear()

    @staticmethod
    def _search(job: DashboardJob, passphrase: str) -> None:
        def progress(stats: SearchStats) -> None:
            with job.lock:
                job.stats = stats

        def sample(candidate: CandidateSample) -> None:
            with job.lock:
                job.sample = candidate
                if not job.samples or job.samples[0]["attempt"] != candidate.attempt:
                    job.samples.appendleft({"attempt": candidate.attempt, "valid": candidate.checksum_valid})

        try:
            if job.operation == "validate":
                started = monotonic()
                valid = is_valid_mnemonic(job.template)
                seeds_derived = derivations = addresses_generated = comparisons = matches = 0
                wallet = None
                if valid:
                    seed = mnemonic_to_seed(job.template, passphrase)
                    seeds_derived = 1
                    wallet = wallet_from_seed(seed, Network.REGTEST)
                    derivations = addresses_generated = comparisons = 1
                address = wallet.address if wallet is not None else None
                if address == job.target:
                    matches = 1
                candidate = CandidateSample(1, job.template, valid, address)
                stats = SearchStats(
                    1, 1 if valid else 0, 0 if valid else 1, monotonic() - started, 1,
                    seeds_derived, derivations, addresses_generated, comparisons, matches,
                )
                sample(candidate)
                progress(stats)
                with job.lock:
                    job.stats, job.status = stats, "found" if address == job.target else "exhausted"
                    if job.status == "found":
                        job.mnemonic, job.wallet = job.template, wallet
                        job.found_at = monotonic()
                job.refresh.set()
                return

            result = brute_force(
                job.template, job.target, network=Network.REGTEST, passphrase=passphrase,
                progress=progress, update_interval=0.25, on_sample=sample, cancel=job.cancel,
                visual_delay=0.02 if job.mode == "visual" else 0.0,
            )
            wallet = result.wallet
            if wallet is not None and wallet.address != job.target:
                raise ValueError("Resultado de derivação inconsistente.")
            with job.lock:
                job.stats, job.status = result.stats, result.status.value
                job.error = result.error
                if result.status == SearchStatus.FOUND:
                    job.mnemonic, job.wallet = result.mnemonic, wallet
                    job.found_at = monotonic()
            job.refresh.set()
        except Exception:
            with job.lock:
                job.status, job.error = "error", "A execução falhou. Limpe o experimento e confira os dados."

    def state(self) -> dict[str, Any]:
        with self._lock:
            job = self._job
            if job is None:
                return {"status": "idle", "network": "regtest", "path": DERIVATION_PATH}
            with job.lock:
                stats = job.stats
                balance = job.balance
                age = max(0.0, monotonic() - balance.checked_at) if balance is not None else None
                fresh = balance is not None and job.balance_error is None and age < 15
                balance_data = {
                    "status": "verified" if fresh else ("unavailable" if job.balance_error or balance else "checking"),
                    "satoshis": balance.satoshis if fresh else None,
                    "height": balance.height if fresh else None,
                    "age_seconds": age,
                    "error": job.balance_error,
                    "after_match": bool(fresh and job.found_at is not None and balance.checked_at >= job.found_at),
                }
                funded = bool(
                    job.status == "found" and balance_data["after_match"] and balance.satoshis > 0
                )
                return {
                    "job_id": job.job_id, "status": job.status, "network": "regtest", "path": DERIVATION_PATH,
                    "target": job.target, "template": job.template, "mode": job.mode,
                    "operation": job.operation,
                    "stats": {
                        **asdict(stats),
                        "remaining_combinations": stats.remaining_combinations,
                        "rate": stats.candidates_per_second,
                        "valid_rate": stats.valid_per_second,
                        "progress": stats.progress_percent,
                        "progress_scaled": stats.progress_scaled,
                        "eta": stats.eta_seconds,
                    },
                    "sample": asdict(job.sample) if job.sample is not None else None,
                    "samples": list(job.samples), "balance": balance_data,
                    "funded_alert": funded, "can_reveal": job.status == "found", "error": job.error,
                }

    def reveal(self, job_id: str) -> dict[str, str]:
        with self._lock:
            job = self._require_job(job_id)
            with job.lock:
                if job.status != "found" or job.wallet is None or job.wallet.address != job.target:
                    raise ValueError("A chave só pode ser revelada depois da correspondência exata com o alvo.")
                return {
                    "mnemonic": job.mnemonic,
                    "private_key_hex": job.wallet.private_key.hex(),
                    "public_key_hex": job.wallet.public_key.hex(),
                    "address": job.wallet.address, "path": DERIVATION_PATH, "network": "regtest",
                }
