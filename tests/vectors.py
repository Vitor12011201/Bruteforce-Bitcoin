"""Public BIP-39 vectors, never real wallet secrets.

Source (MIT): https://github.com/trezor/python-mnemonic/blob/master/vectors.json
Copyright (c) 2013-2016 Pavol Rusnak, 2017-2024 Trezor. Passphrase: TREZOR.
"""

BIP39_VECTORS = (
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
)

PUBLIC_MNEMONIC = BIP39_VECTORS[0][1]
PUBLIC_SEED_EMPTY_PASSPHRASE = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5"
    "ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
PUBLIC_MASTER_TREZOR = (
    "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbe"
    "F1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
)
# Published BIP-84 testnet/regtest fixtures (MIT), same public mnemonic, empty passphrase:
# https://github.com/ebellocchia/bip_utils/blob/master/tests/bip/bip84/test_bip84.py
PUBLIC_TESTNET_ADDRESS = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
PUBLIC_REGTEST_ADDRESS = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk"
