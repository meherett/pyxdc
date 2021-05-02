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


def test_from_wallet_important_format():

    wallet: Wallet = Wallet(
        provider=HTTP_PROVIDER
    ).from_wif(
        wif=_["wallet"]["wif"]
    )

    assert wallet.strength() is None
    assert wallet.entropy() is None
    assert wallet.mnemonic() is None
    assert wallet.language() is None
    assert wallet.passphrase() is None
    assert wallet.seed() is None
    assert wallet.root_xprivate_key(encoded=True) is None
    assert wallet.root_xprivate_key(encoded=False) is None
    assert wallet.root_xpublic_key(encoded=True) is None
    assert wallet.root_xpublic_key(encoded=False) is None
    assert wallet.xprivate_key(encoded=True) is None
    assert wallet.xprivate_key(encoded=False) is None
    assert wallet.xpublic_key(encoded=True) is None
    assert wallet.xpublic_key(encoded=False) is None
    assert wallet.uncompressed() == _["wallet"]["uncompressed"]
    assert wallet.compressed() == _["wallet"]["compressed"]
    assert wallet.private_key() == _["wallet"]["private_key"]
    assert wallet.public_key() == _["wallet"]["public_key"]
    assert wallet.wif() == _["wallet"]["wif"]
    assert wallet.finger_print() == _["wallet"]["finger_print"]
    assert wallet.semantic() == _["wallet"]["semantic"]
    assert wallet.path() is None
    assert wallet.hash() == _["wallet"]["hash"]
    assert wallet.address(prefix="xdc") == _["wallet"]["address_xdc"]
    assert wallet.address(prefix="0x") == _["wallet"]["address_0x"]

    assert isinstance(wallet.dumps(), dict)
    # assert isinstance(wallet.balance(unit="XDC"), float)

    signature: str = wallet.sign(message=MESSAGE)
    assert isinstance(signature, str)
    assert wallet.verify(signature=signature, message=MESSAGE)
