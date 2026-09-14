import unittest

from bip_utils import Bip32Secp256k1, SegwitBech32Encoder

from bip39_lab.wallet import (
    DERIVATION_PATH,
    WORDLIST,
    Network,
    derive_wallet,
    generate_mnemonic,
    is_valid_mnemonic,
    mnemonic_from_entropy,
    mnemonic_to_seed,
    validate_target_address,
    wallet_from_seed,
)
from tests.vectors import (
    BIP39_VECTORS,
    PUBLIC_MASTER_TREZOR,
    PUBLIC_MNEMONIC,
    PUBLIC_REGTEST_ADDRESS,
    PUBLIC_SEED_EMPTY_PASSPHRASE,
    PUBLIC_TESTNET_ADDRESS,
)


class WalletTests(unittest.TestCase):
    def test_official_bip39_vectors(self) -> None:
        for entropy_hex, phrase, seed_hex in BIP39_VECTORS:
            with self.subTest(entropy=entropy_hex):
                self.assertEqual(mnemonic_from_entropy(bytes.fromhex(entropy_hex)), phrase)
                self.assertTrue(is_valid_mnemonic(phrase))
                self.assertEqual(mnemonic_to_seed(phrase, "TREZOR").hex(), seed_hex)

    def test_empty_passphrase_vector(self) -> None:
        self.assertEqual(mnemonic_to_seed(PUBLIC_MNEMONIC).hex(), PUBLIC_SEED_EMPTY_PASSPHRASE)

    def test_official_bip32_master(self) -> None:
        master = Bip32Secp256k1.FromSeed(mnemonic_to_seed(PUBLIC_MNEMONIC, "TREZOR"))
        self.assertEqual(master.PrivateKey().ToExtended(), PUBLIC_MASTER_TREZOR)

    def test_generation_has_12_valid_words(self) -> None:
        phrase = generate_mnemonic()
        self.assertEqual(len(phrase.split()), 12)
        self.assertTrue(is_valid_mnemonic(phrase))

    def test_wordlist(self) -> None:
        self.assertEqual(len(WORDLIST), 2048)
        self.assertEqual(len(set(WORDLIST)), 2048)
        self.assertEqual(WORDLIST[0], "abandon")
        self.assertEqual(WORDLIST[-1], "zoo")

    def test_invalid_mnemonic_rejected(self) -> None:
        for phrase in ("abandon " * 12, "abandon " * 11, "abandon " * 24, "INVALID " * 12):
            with self.subTest(words=len(phrase.split())):
                self.assertFalse(is_valid_mnemonic(phrase))
                with self.assertRaises(ValueError):
                    derive_wallet(phrase)

    def test_wrong_entropy_and_seed_lengths(self) -> None:
        for length in (0, 15, 17, 32):
            with self.subTest(length=length), self.assertRaises(ValueError):
                mnemonic_from_entropy(bytes(length))
        for length in (0, 16, 32, 63, 65):
            with self.subTest(length=length), self.assertRaises(ValueError):
                wallet_from_seed(bytes(length))

    def test_nfkd_passphrase_and_word_whitespace(self) -> None:
        self.assertEqual(mnemonic_to_seed(PUBLIC_MNEMONIC, "café"), mnemonic_to_seed(PUBLIC_MNEMONIC, "cafe\u0301"))
        spaced = "\t" + "\n  ".join(PUBLIC_MNEMONIC.split()) + "  "
        self.assertEqual(mnemonic_to_seed(spaced), mnemonic_to_seed(PUBLIC_MNEMONIC))
        self.assertNotEqual(mnemonic_to_seed(PUBLIC_MNEMONIC, " "), mnemonic_to_seed(PUBLIC_MNEMONIC))

    def test_testnet_determinism_and_published_address(self) -> None:
        first = derive_wallet(PUBLIC_MNEMONIC)
        second = derive_wallet(PUBLIC_MNEMONIC)
        self.assertEqual(first, second)
        self.assertEqual(first.address, PUBLIC_TESTNET_ADDRESS)
        self.assertEqual(first.derivation_path, DERIVATION_PATH)
        self.assertEqual(len(first.private_key), 32)
        self.assertEqual(len(first.public_key), 33)

    def test_bip84_matches_explicit_bip32_path_and_keys(self) -> None:
        wallet = derive_wallet(PUBLIC_MNEMONIC)
        node = Bip32Secp256k1.FromSeed(mnemonic_to_seed(PUBLIC_MNEMONIC)).DerivePath(DERIVATION_PATH)
        self.assertEqual(wallet.private_key, node.PrivateKey().Raw().ToBytes())
        self.assertEqual(wallet.public_key, node.PublicKey().RawCompressed().ToBytes())

    def test_regtest_uses_same_path_and_different_address_encoding(self) -> None:
        regtest = derive_wallet(PUBLIC_MNEMONIC, Network.REGTEST)
        testnet = derive_wallet(PUBLIC_MNEMONIC)
        self.assertEqual(regtest.address, PUBLIC_REGTEST_ADDRESS)
        self.assertEqual(regtest.private_key, testnet.private_key)
        self.assertEqual(regtest.public_key, testnet.public_key)
        self.assertEqual(validate_target_address(regtest.address, Network.REGTEST), regtest.address)

    def test_nonempty_passphrase_changes_address(self) -> None:
        self.assertNotEqual(derive_wallet(PUBLIC_MNEMONIC, passphrase="TREZOR").address, PUBLIC_TESTNET_ADDRESS)

    def test_mainnet_network_is_unavailable(self) -> None:
        with self.assertRaises(ValueError):
            Network("mainnet")
        with self.assertRaises(ValueError):
            derive_wallet(PUBLIC_MNEMONIC, "mainnet")  # type: ignore[arg-type]

    def test_target_validation_rejects_other_networks_and_corruption(self) -> None:
        for address in (
            "", PUBLIC_TESTNET_ADDRESS.upper(), " " + PUBLIC_TESTNET_ADDRESS,
            PUBLIC_TESTNET_ADDRESS[:-1] + "q", PUBLIC_REGTEST_ADDRESS,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ):
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_target_address(address)
        self.assertEqual(validate_target_address(PUBLIC_TESTNET_ADDRESS), PUBLIC_TESTNET_ADDRESS)

    def test_valid_p2wsh_and_taproot_are_rejected(self) -> None:
        for version in (0, 1):
            address = SegwitBech32Encoder.Encode("tb", version, bytes([1]) * 32)
            with self.subTest(version=version), self.assertRaises(ValueError):
                validate_target_address(address)

    def test_wallet_repr_does_not_expose_keys(self) -> None:
        wallet = derive_wallet(PUBLIC_MNEMONIC)
        self.assertNotIn("private_key", repr(wallet))
        self.assertNotIn(wallet.private_key.hex(), repr(wallet))
