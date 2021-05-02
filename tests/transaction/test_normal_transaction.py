#!/usr/bin/env python3

import json
import os

from pyxdc import WEBSOCKET_PROVIDER
from pyxdc.transaction import NormalTransaction
from pyxdc.utils import amount_unit_converter
from pyxdc.wallet import Wallet

# Test Values
base_path = os.path.dirname(__file__)
file_path = os.path.abspath(os.path.join(base_path, "..", "values.json"))
values = open(file_path, "r", encoding="utf-8")
_ = json.loads(values.read())
values.close()


def test_normal_transaction():

    wallet: Wallet = Wallet(
        provider=WEBSOCKET_PROVIDER
    ).from_entropy(
        entropy=_["wallet"]["entropy"],
        passphrase=_["wallet"]["passphrase"],
        language=_["wallet"]["language"]
    ).from_path(
        path=_["wallet"]["path"]
    )

    normal_transaction: NormalTransaction = NormalTransaction(
        provider=WEBSOCKET_PROVIDER
    )

    normal_transaction.build_transaction(
        address=wallet.address(prefix="xdc"),
        recipient="xdc9Cd6fD3519b259B251d881361CAae6BABdC5910b",
        value=amount_unit_converter(amount=0.1, unit="XDC2Wei")
    )

    normal_transaction.sign_transaction(
        root_xprivate_key=_["wallet"]["root_xprivate_key"],
        path=_["wallet"]["path"]
    )

    assert normal_transaction.fee() == _["transaction"]["normal_transaction"]["fee"]
    assert normal_transaction.hash() == _["transaction"]["normal_transaction"]["hash"]
    assert normal_transaction.raw() == _["transaction"]["normal_transaction"]["raw"]
    assert normal_transaction.json() == _["transaction"]["normal_transaction"]["json"]
