#!/usr/bin/env python3

import json
import os

from pyxdc.signature import (
    sign, verify
)

# Test Values
base_path = os.path.dirname(__file__)
file_path = os.path.abspath(os.path.join(base_path, "values.json"))
values = open(file_path, "r", encoding="utf-8")
_ = json.loads(values.read())
values.close()

MESSAGE: str = "meherett"

MESSAGE_HASH: str = "4bbbfd0c33fea618f4a9aa75c02fe76e50fa59798af021bc34f7856f3259c685"


def test_signature():

    signature = sign(private_key=_["wallet"]["private_key"], message=MESSAGE)
    assert isinstance(signature, str)
    assert verify(public_key=_["wallet"]["public_key"], signature=signature, message=MESSAGE)

    signature = sign(private_key=_["wallet"]["private_key"], message_hash=MESSAGE_HASH)
    assert isinstance(signature, str)
    assert verify(public_key=_["wallet"]["public_key"], signature=signature, message_hash=MESSAGE_HASH)
