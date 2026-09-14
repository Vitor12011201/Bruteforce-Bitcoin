"""Loopback-only laboratory HTTP server; never a public wallet service."""

import json
import secrets
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from bip39_lab.balance import DEFAULT_COOKIE_FILE, DEFAULT_RPC_PORT, BalanceUnavailable, RegtestBalanceClient
from bip39_lab.dashboard import Dashboard


ASSETS = Path(__file__).parent / "static"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATE_INTEGER_FIELDS = frozenset({
    "attempts", "valid_mnemonics", "rejected_checksum", "total_combinations",
    "remaining_combinations", "progress_scaled", "seeds_derived", "derivations",
    "addresses_generated", "comparisons", "matches", "in_flight",
})


def serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    """Keep discrete counters exact across JSON.parse in the browser."""
    result = dict(state)
    stats = result.get("stats")
    if isinstance(stats, dict):
        result["stats"] = {
            key: str(value) if key in STATE_INTEGER_FIELDS and isinstance(value, int) else value
            for key, value in stats.items()
        }
    sample = result.get("sample")
    if isinstance(sample, dict) and isinstance(sample.get("attempt"), int):
        result["sample"] = {**sample, "attempt": str(sample["attempt"])}
    samples = result.get("samples")
    if isinstance(samples, list):
        result["samples"] = [
            {**row, "attempt": str(row["attempt"])}
            if isinstance(row, dict) and isinstance(row.get("attempt"), int) else row
            for row in samples
        ]
    return result


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, dashboard: Dashboard) -> None:
        self.dashboard = dashboard
        self.token = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", port), LabHandler)


class LabHandler(BaseHTTPRequestHandler):
    server: LabServer
    server_version = "BIP39Lab"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, value: Any) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))

    def _check_request(self, *, api: bool = False, mutation: bool = False) -> bool:
        host = self.headers.get("Host", "")
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        origin = self.headers.get("Origin")
        if host not in allowed or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._json(403, {"error": "Acesso permitido somente pela interface local."})
            return False
        if (origin is not None and origin != f"http://{host}") or (mutation and origin is None):
            self._json(403, {"error": "Origem da requisição não permitida."})
            return False
        provided_token = self.headers.get("X-Lab-Token", "")
        if api and (not provided_token.isascii() or not secrets.compare_digest(provided_token, self.server.token)):
            self._json(403, {"error": "Sessão inválida. Recarregue a página local."})
            return False
        return True

    def do_GET(self) -> None:
        if not self._check_request(api=self.path.startswith("/api/")):
            return
        if self.path == "/api/state":
            self._json(200, serialize_state(self.server.dashboard.state()))
            return
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/favicon.svg": ("favicon.svg", "image/svg+xml"),
        }
        if self.path not in assets:
            self._json(404, {"error": "Rota não encontrada."})
            return
        name, content_type = assets[self.path]
        body = (ASSETS / name).read_bytes()
        if name == "index.html":
            body = body.replace(b"__LAB_TOKEN__", self.server.token.encode("ascii"))
        self._send(200, body, content_type)

    def _read_body(self) -> dict[str, Any]:
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            raise ValueError("Envie dados JSON pela interface local.")
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Formato de requisição não permitido.")
        length = int(self.headers.get("Content-Length", "0"))
        if not 1 <= length <= 8192:
            raise ValueError("Dados ausentes ou grandes demais.")
        body = json.loads(self.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("Os dados devem ser um objeto JSON.")
        return body

    @staticmethod
    def _text(body: dict[str, Any], name: str, maximum: int, default: str = "") -> str:
        value = body.get(name, default)
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError(f"Campo {name} inválido.")
        return value

    def do_POST(self) -> None:
        if not self._check_request(api=True, mutation=True):
            return
        try:
            body = self._read_body()
            dashboard = self.server.dashboard
            if self.path in {"/api/generate", "/api/example"}:
                passphrase = self._text(body, "passphrase", 1024) if self.path == "/api/generate" else ""
                result = dashboard.generate(passphrase, example=self.path == "/api/example")
            elif self.path == "/api/start":
                result = {"job_id": dashboard.start(
                    self._text(body, "target", 100), self._text(body, "template", 500),
                    self._text(body, "passphrase", 1024), self._text(body, "mode", 20, "visual"),
                    self._text(body, "operation", 20, "limited"),
                )}
            elif self.path == "/api/stop":
                dashboard.stop(self._text(body, "job_id", 50))
                result = {"ok": True}
            elif self.path == "/api/clear":
                dashboard.clear()
                result = {"ok": True}
            elif self.path == "/api/reveal":
                result = dashboard.reveal(self._text(body, "job_id", 50))
            else:
                self._json(404, {"error": "Rota não encontrada."})
                return
            self._json(200, result)
        except (json.JSONDecodeError, UnicodeError):
            self._json(400, {"error": "JSON inválido. Recarregue a interface local."})
        except ValueError as error:
            self._json(400, {"error": str(error)})
        except (OSError, TimeoutError):
            self._json(408, {"error": "A requisição não foi concluída a tempo."})


def start_regtest_node() -> None:
    directory = PROJECT_ROOT / ".lab-regtest"
    cookie = directory / "regtest" / ".cookie"
    probe = RegtestBalanceClient(Dashboard.generate(example=True)["target"], cookie_file=cookie)
    try:
        chain = probe._rpc("getblockchaininfo", [])
    except BalanceUnavailable:
        pass
    else:
        if chain.get("chain") != "regtest":
            raise ValueError("A porta local configurada não corresponde a um nó regtest.")
        return
    directory.mkdir(mode=0o700, exist_ok=True)
    try:
        process = subprocess.run([
            "bitcoind", "-regtest=1", f"-datadir={directory}", "-conf=/dev/null", "-nosettings",
            "-server=1", "-disablewallet=1", "-networkactive=0", "-listen=0", "-dnsseed=0",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=18443", "-nodebuglogfile", "-daemonwait",
        ], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Não foi possível iniciar Bitcoin Core. Confira a instalação e a porta 18443.") from None
    if process.returncode != 0:
        raise ValueError("O nó regtest não iniciou. Confira se a porta 18443 está livre.")


def serve(port: int = 8765, *, start_node: bool = False, cookie_file: Path = DEFAULT_COOKIE_FILE, rpc_port: int = DEFAULT_RPC_PORT) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Escolha uma porta web entre 1024 e 65535.")
    if start_node:
        if cookie_file != DEFAULT_COOKIE_FILE or rpc_port != DEFAULT_RPC_PORT:
            raise ValueError("--start-regtest usa o nó padrão do laboratório; omita a opção para usar um nó próprio.")
        start_regtest_node()
        cookie_file = PROJECT_ROOT / DEFAULT_COOKIE_FILE
    dashboard = Dashboard(cookie_file, rpc_port)
    try:
        server = LabServer(port, dashboard)
    except OSError:
        raise ValueError("A porta web está indisponível. Escolha outra com --port.") from None
    print(f"Painel local: http://127.0.0.1:{port} — somente regtest. Ctrl+C encerra o painel.", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.clear()
        server.server_close()
