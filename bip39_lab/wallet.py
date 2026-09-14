"""BIP-39 and BIP-84 derivation using established cryptographic libraries."""

from dataclasses import dataclass, field
from enum import Enum

from bip_utils import Bip44Changes, Bip84, Bip84Coins, P2WPKHAddrDecoder
from mnemonic import Mnemonic


DERIVATION_PATH = "m/84'/1'/0'/0/0"
_BIP39 = Mnemonic("english")
WORDLIST: tuple[str, ...] = tuple(_BIP39.wordlist)
WORD_SET: frozenset[str] = frozenset(WORDLIST)


class Network(str, Enum):
    TESTNET = "testnet"
    REGTEST = "regtest"

    @property
    def hrp(self) -> str:
        return {Network.TESTNET: "tb", Network.REGTEST: "bcrt"}[self]

    @property
    def coin(self) -> Bip84Coins:
        return {
            Network.TESTNET: Bip84Coins.BITCOIN_TESTNET,
            Network.REGTEST: Bip84Coins.BITCOIN_REGTEST,
        }[self]


@dataclass(frozen=True)
class Wallet:
    address: str
    network: Network
    private_key: bytes = field(repr=False)
    public_key: bytes = field(repr=False)
    derivation_path: str = DERIVATION_PATH


def normalize_words(phrase: str) -> str:
    return " ".join(Mnemonic.normalize_string(phrase).split())


def is_valid_mnemonic(phrase: str) -> bool:
    normalized = normalize_words(phrase)
    return len(normalized.split()) == 12 and _BIP39.check(normalized)


def mnemonic_from_entropy(entropy: bytes) -> str:
    """Explicit entropy is useful for public test vectors, never user randomness."""
    if len(entropy) != 16:
        raise ValueError("O laboratório aceita somente 128 bits de entropia (16 bytes).")
    return _BIP39.to_mnemonic(entropy)


def generate_mnemonic() -> str:
    """The reference implementation obtains randomness from Python secrets."""
    return _BIP39.generate(strength=128)


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    normalized = normalize_words(phrase)
    if not is_valid_mnemonic(normalized):
        raise ValueError("Mnemonic inválida: são necessárias 12 palavras English e checksum válido.")
    return Mnemonic.to_seed(normalized, passphrase=passphrase)


def wallet_from_seed(seed: bytes, network: Network = Network.TESTNET) -> Wallet:
    network = Network(network)
    if len(seed) != 64:
        raise ValueError("Uma seed BIP-39 deve conter 64 bytes.")
    node = (
        Bip84.FromSeed(seed, network.coin)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    return Wallet(
        address=node.PublicKey().ToAddress(),
        network=network,
        private_key=node.PrivateKey().Raw().ToBytes(),
        public_key=node.PublicKey().RawCompressed().ToBytes(),
    )


def derive_wallet(
    phrase: str, network: Network = Network.TESTNET, passphrase: str = ""
) -> Wallet:
    network = Network(network)
    return wallet_from_seed(mnemonic_to_seed(phrase, passphrase), network)


def validate_target_address(address: str, network: Network = Network.TESTNET) -> str:
    network = Network(network)
    if not address or address != address.lower() or address != address.strip():
        raise ValueError("Use um endereço-alvo canônico em minúsculas, sem espaços.")
    try:
        program = P2WPKHAddrDecoder.DecodeAddr(address, hrp=network.hrp)
    except ValueError:
        raise ValueError(f"Endereço-alvo P2WPKH inválido para {network.value}.") from None
    # The library's witness-v0 decoder also accepts 32-byte P2WSH programs.
    if len(program) != 20:
        raise ValueError("O alvo deve ser P2WPKH (SegWit v0, hash de 20 bytes).")
    return address
