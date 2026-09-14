"""Read confirmed UTXOs for one fixed target from a local regtest node."""

import base64
import json
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic
from typing import Any

from bip39_lab.wallet import Network, validate_target_address


DEFAULT_COOKIE_FILE = Path(".lab-regtest/regtest/.cookie")
DEFAULT_RPC_PORT = 18443
POLL_INTERVAL = 5.0
RPC_TIMEOUT = 3.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SATOSHIS_PER_BTC = 100_000_000


class BalanceUnavailable(Exception):
    """A balance could not be verified; this never means a zero balance."""


@dataclass(frozen=True)
class TargetBalance:
    satoshis: int
    height: int
    bestblock: str
    checked_at: float


class RegtestBalanceClient:
    def __init__(
        self,
        target_address: str,
        *,
        cookie_file: Path = DEFAULT_COOKIE_FILE,
        port: int = DEFAULT_RPC_PORT,
    ) -> None:
        self._target = validate_target_address(target_address, Network.REGTEST)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("A porta RPC deve estar entre 1 e 65535.")
        self._cookie_file = Path(cookie_file)
        self._port = port
        self._cached: TargetBalance | None = None

    def _rpc(self, method: str, params: list[Any]) -> dict[str, Any]:
        if method not in {"getblockchaininfo", "scantxoutset"}:
            raise BalanceUnavailable("Método RPC não permitido pelo monitor.")
        try:
            cookie = self._cookie_file.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise BalanceUnavailable("Cookie RPC indisponível; inicie o nó regtest local.") from None
        if not cookie or ":" not in cookie or "\n" in cookie:
            raise BalanceUnavailable("Cookie RPC inválido.")
        authorization = base64.b64encode(cookie.encode("utf-8")).decode("ascii")
        connection = HTTPConnection("127.0.0.1", self._port, timeout=RPC_TIMEOUT)
        try:
            connection.request(
                "POST", "/",
                body=json.dumps({"jsonrpc": "2.0", "id": "lab-balance", "method": method, "params": params}),
                headers={"Content-Type": "application/json", "Authorization": f"Basic {authorization}"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise BalanceUnavailable(f"RPC local indisponível (HTTP {response.status}).")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise BalanceUnavailable("Resposta RPC excede o limite do laboratório.")
            payload = json.loads(body, parse_float=Decimal)
        except (OSError, HTTPException):
            raise BalanceUnavailable("Nó RPC sem resposta; saldo desconhecido.") from None
        except (ValueError, UnicodeError):
            raise BalanceUnavailable("Resposta RPC inválida; saldo desconhecido.") from None
        finally:
            connection.close()
        if not isinstance(payload, dict) or payload.get("id") != "lab-balance":
            raise BalanceUnavailable("Resposta RPC inválida; saldo desconhecido.")
        if payload.get("error") is not None or not isinstance(payload.get("result"), dict):
            raise BalanceUnavailable("O nó recusou a consulta; outra consulta UTXO pode estar em andamento.")
        return payload["result"]

    def fetch(self) -> TargetBalance:
        chain = self._rpc("getblockchaininfo", [])
        if chain.get("chain") != "regtest":
            self._cached = None
            raise BalanceUnavailable("Conexão recusada: o nó precisa estar em REGTEST.")
        if self._cached is not None and chain.get("bestblockhash") == self._cached.bestblock:
            self._cached = replace(self._cached, checked_at=monotonic())
            return self._cached
        result = self._rpc("scantxoutset", ["start", [f"addr({self._target})"]])
        if result.get("success") is not True:
            raise BalanceUnavailable("Consulta UTXO incompleta; saldo desconhecido.")
        try:
            amount = Decimal(str(result["total_amount"])) * SATOSHIS_PER_BTC
            height = result["height"]
            bestblock = result["bestblock"]
            if (
                not amount.is_finite() or amount < 0 or amount != amount.to_integral_value()
                or type(height) is not int or height < 0
                or not isinstance(bestblock, str) or len(bestblock) != 64
                or any(character not in "0123456789abcdef" for character in bestblock)
            ):
                raise ValueError
        except (KeyError, ValueError, InvalidOperation):
            raise BalanceUnavailable("Dados de saldo inválidos na resposta RPC.") from None
        self._cached = TargetBalance(int(amount), height, bestblock, monotonic())
        return self._cached


class TargetBalanceMonitor:
    def __init__(self, client: RegtestBalanceClient) -> None:
        self._client = client
        self._lock = Lock()
        self._stop = Event()
        self._balance: TargetBalance | None = None
        self._error: str | None = None
        self._thread: Thread | None = None

    def _refresh(self) -> None:
        try:
            balance = self._client.fetch()
        except BalanceUnavailable as error:
            with self._lock:
                self._error = str(error)
        else:
            with self._lock:
                self._balance = balance
                self._error = None

    def _poll(self) -> None:
        while not self._stop.wait(POLL_INTERVAL):
            self._refresh()

    def __enter__(self) -> "TargetBalanceMonitor":
        # Initial lookup precedes search timing; later lookups run in the background.
        self._refresh()
        self._thread = Thread(target=self._poll, name="lab-target-balance", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.1)

    def status_line(self) -> str:
        with self._lock:
            balance, error = self._balance, self._error
        if error is not None:
            return f"Saldo do ALVO: indisponível (não significa zero). {error}"
        if balance is None:
            return "Saldo do ALVO: consultando nó regtest local..."
        age = max(0.0, monotonic() - balance.checked_at)
        amount = Decimal(balance.satoshis) / SATOSHIS_PER_BTC
        return (
            f"Saldo do ALVO: {amount:.8f} BTC de teste (regtest) | "
            f"{balance.satoshis:,} sat | Bloco: {balance.height} | "
            f"Verificado há {age:.1f}s | UTXOs confirmados; pode incluir coinbase imatura"
        )
