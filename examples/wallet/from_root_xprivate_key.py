#!/usr/bin/env python3

from pyxdc import HTTP_PROVIDER
from pyxdc.wallet import Wallet
from pyxdc.utils import (
    amount_unit_converter, is_root_xprivate_key
)

import json

# XinFin root xprivate key
ROOT_XPRIVATE_KEY: str = "xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH" \
                         "7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz"

# Check XinFin root xprivate key
assert is_root_xprivate_key(xprivate_key=ROOT_XPRIVATE_KEY)

# Initialize XinFin mainnet Wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin Wallet from root xprivate key
wallet.from_root_xprivate_key(root_xprivate_key=ROOT_XPRIVATE_KEY)

# Derivation from path
wallet.from_path("m/44'/550'/0'/0/0")
# Or derivation from index
# wallet.from_index(44, hardened=True)
# wallet.from_index(550, hardened=True)
# wallet.from_index(0, hardened=True)
# wallet.from_index(0)
# wallet.from_index(0)

# Print all XinFin Wallet information's
# print(json.dumps(wallet.dumps(), indent=4, ensure_ascii=False))

print("Root XPrivate Key:", wallet.root_xprivate_key())
print("Root XPublic Key:", wallet.root_xpublic_key())
print("XPrivate Key:", wallet.xprivate_key())
print("XPublic Key:", wallet.xpublic_key())
print("Uncompressed:", wallet.uncompressed())
print("Compressed:", wallet.compressed())
print("Chain Code:", wallet.chain_code())
print("Private Key:", wallet.private_key())
print("Public Key:", wallet.public_key())
print("Wallet Important Format:", wallet.wif())
print("Finger Print:", wallet.finger_print())
print("Semantic:", wallet.semantic())
print("Path:", wallet.path())
print("Hash:", wallet.hash())
print("Address:", wallet.address())
print("Balance:", amount_unit_converter(amount=wallet.balance(), unit="Wei2XDC"), "XDC")

print("-------- Sign & Verify --------")

MESSAGE_HASH: str = "34482808c8f9e9c78b9ba295438160cc5f1cc24d5bfd992aaef0602319cb379b"

print("Message Hash:", MESSAGE_HASH)
signature: str = wallet.sign(message_hash=MESSAGE_HASH)
print("Signature:", signature)
print("Verified:", wallet.verify(signature=signature, message_hash=MESSAGE_HASH))
