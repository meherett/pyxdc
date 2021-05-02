#!/usr/bin/env python3

import json
import os

from pyxdc import HTTP_PROVIDER
from pyxdc.wallet import Wallet

# Test Values
base_path = os.path.dirname(__file__)
file_path = os.path.abspath(os.path.join(base_path, "..", "values.json"))
values = open(file_path, "r", encoding="utf-8")
_ = json.loads(values.read())
values.close()

MESSAGE: str = "meherett"


def test_from_mnemonic():

    wallet: Wallet = Wallet(
        provider=HTTP_PROVIDER
    ).from_mnemonic(
        mnemonic=_["wallet"]["mnemonic"],
        passphrase=_["wallet"]["passphrase"],
        language=_["wallet"]["language"]
    ).from_path(
        path=_["wallet"]["path"]
    )

    assert wallet.strength() == _["wallet"]["strength"]
    assert wallet.entropy() == _["wallet"]["entropy"]
    assert wallet.mnemonic() == _["wallet"]["mnemonic"]
    assert wallet.language() == _["wallet"]["language"]
    assert wallet.passphrase() is None
    assert wallet.seed() == _["wallet"]["seed"]
    assert wallet.root_xprivate_key(encoded=True) == _["wallet"]["root_xprivate_key"]
    assert wallet.root_xprivate_key(encoded=False) == _["wallet"]["root_xprivate_key_hex"]
    assert wallet.root_xpublic_key(encoded=True) == _["wallet"]["root_xpublic_key"]
    assert wallet.root_xpublic_key(encoded=False) == _["wallet"]["root_xpublic_key_hex"]
    assert wallet.xprivate_key(encoded=True) == _["wallet"]["xprivate_key"]
    assert wallet.xprivate_key(encoded=False) == _["wallet"]["xprivate_key_hex"]
    assert wallet.xpublic_key(encoded=True) == _["wallet"]["xpublic_key"]
    assert wallet.xpublic_key(encoded=False) == _["wallet"]["xpublic_key_hex"]
    assert wallet.uncompressed() == _["wallet"]["uncompressed"]
    assert wallet.compressed() == _["wallet"]["compressed"]
    assert wallet.private_key() == _["wallet"]["private_key"]
    assert wallet.public_key() == _["wallet"]["public_key"]
    assert wallet.wif() == _["wallet"]["wif"]
    assert wallet.finger_print() == _["wallet"]["finger_print"]
    assert wallet.semantic() == _["wallet"]["semantic"]
    assert wallet.path() == _["wallet"]["path"]
    assert wallet.hash() == _["wallet"]["hash"]
    assert wallet.address(prefix="xdc") == _["wallet"]["address_xdc"]
    assert wallet.address(prefix="0x") == _["wallet"]["address_0x"]

    assert isinstance(wallet.dumps(), dict)
    # assert isinstance(wallet.balance(unit="XDC"), float)

    signature: str = wallet.sign(message=MESSAGE)
    assert isinstance(signature, str)
    assert wallet.verify(signature=signature, message=MESSAGE)
