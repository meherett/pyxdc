#!/usr/bin/env python3

import json
import unicodedata
import os

from pyxdc.utils import (
    generate_entropy, generate_mnemonic, is_entropy, is_mnemonic, get_mnemonic_language,
    get_entropy_strength, get_mnemonic_strength, is_address, is_checksum_address, to_checksum_address,
    get_bytes, is_root_xprivate_key, is_root_xpublic_key
)

# Test Values
base_path: str = os.path.dirname(__file__)
file_path: str = os.path.abspath(os.path.join(base_path, "values.json"))
values = open(file_path, "r", encoding="utf-8")
_: dict = json.loads(values.read())
values.close()


def test_utils():

    assert isinstance(get_bytes(string=b"meherett"), bytes)

    assert is_address("xdc1ee11011ae12103a488a82dc33e03f337bc93ba7")
    assert is_address("xdc1Ee11011ae12103a488A82DC33e03f337Bc93ba7")

    assert not is_checksum_address("xdc1ee11011ae12103a488a82dc33e03f337bc93ba7")
    assert is_checksum_address("xdc1Ee11011ae12103a488A82DC33e03f337Bc93ba7")

    assert to_checksum_address("xdc1ee11011ae12103a488a82dc33e03f337bc93ba7") == "xdc1Ee11011ae12103a488A82DC33e03f337Bc93ba7"

    assert is_root_xprivate_key(xprivate_key=_["wallet"]["root_xprivate_key"])
    assert not is_root_xprivate_key(xprivate_key=_["wallet"]["xprivate_key"])

    assert is_root_xpublic_key(xpublic_key=_["wallet"]["root_xpublic_key"])
    assert not is_root_xpublic_key(xpublic_key=_["wallet"]["xpublic_key"])


def test_utils_entropy():

    assert len(generate_entropy(strength=128)) == 32
    assert len(generate_entropy(strength=160)) == 40
    assert len(generate_entropy(strength=192)) == 48
    assert len(generate_entropy(strength=224)) == 56
    assert len(generate_entropy(strength=256)) == 64

    for entropy in _["utils"]["entropy's"]:

        assert len(entropy["entropy"]) == entropy["length"]
        assert get_entropy_strength(entropy["entropy"]) == entropy["strength"]
        assert is_entropy(entropy["entropy"])


def test_utils_mnemonic():

    assert len(generate_mnemonic(strength=128).split(" ")) == 12
    assert len(generate_mnemonic(strength=160).split(" ")) == 15
    assert len(generate_mnemonic(strength=192).split(" ")) == 18
    assert len(generate_mnemonic(strength=224).split(" ")) == 21
    assert len(generate_mnemonic(strength=256).split(" ")) == 24

    for mnemonic in _["utils"]["mnemonics"]:

        assert len(unicodedata.normalize("NFKD", mnemonic["mnemonic"]).split(" ")) == mnemonic["words"]
        assert get_mnemonic_strength(mnemonic["mnemonic"]) == mnemonic["strength"]
        assert is_mnemonic(mnemonic["mnemonic"])
        if mnemonic["language"] == "english":
            assert not is_mnemonic(mnemonic["mnemonic"], "korean")
        assert is_mnemonic(mnemonic["mnemonic"], mnemonic["language"])
        assert get_mnemonic_language(mnemonic["mnemonic"]) == mnemonic["language"]
