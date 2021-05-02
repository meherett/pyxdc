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

    with pytest.raises(ValueError, match="Could not format invalid value 'xdc9cd6fd3519b259b251d881361caae6babdc5910b' as field 'from'"):
        get_transaction(transaction_hash=TRANSACTION_HASH, provider=HTTP_PROVIDER)
