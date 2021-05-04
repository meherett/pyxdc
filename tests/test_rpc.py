#!/usr/bin/env python3

import pytest
import json
import os

from pyxdc import HTTP_PROVIDER
from pyxdc.rpc import (
    get_balance, get_transaction, submit_transaction_raw
)

# Test Values
base_path = os.path.dirname(__file__)
file_path = os.path.abspath(os.path.join(base_path, "values.json"))
values = open(file_path, "r", encoding="utf-8")
_ = json.loads(values.read())
values.close()

TRANSACTION_HASH: str = "0xad01d3e4524e0f8d9cd7476afdad31fafb6b9b92c2052159567f9f6f3d58cb23"


def test_rpc():

    assert isinstance(get_balance(address=_["wallet"]["address_xdc"], provider=HTTP_PROVIDER), int)
    assert isinstance(get_balance(address=_["wallet"]["address_0x"], provider=HTTP_PROVIDER), int)

    assert get_transaction(transaction_hash=TRANSACTION_HASH) == {
        "blockHash": "0x1e73eb53a11c2a5c510c5ec5ec58fffab2f7b6c28664398c6eebeaf6c00b8dc3",
        "blockNumber": 29360748,
        "from": "xdc9Cd6fD3519b259B251d881361CAae6BABdC5910b",
        "gas": 21000,
        "gasPrice": "250000000",
        "hash": "0xad01d3e4524e0f8d9cd7476afdad31fafb6b9b92c2052159567f9f6f3d58cb23",
        "input": "0x",
        "nonce": 0,
        "to": "xdcAF78a3fc5FEf31F374910873D9A8fc70d2F193f8",
        "transactionIndex": 0,
        "value": "50000000000000000000",
        "v": "0x1b",
        "r": "0x1102ce0627362290aa7b087ef5fb943a091759ad61eb88de83eaf33489bbfbed",
        "s": "0x11845e2828c90f473bcf514cebd48671b8e0b74716a9eed741b7e7fdd77b047a"
    }
