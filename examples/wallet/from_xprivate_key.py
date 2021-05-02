#!/usr/bin/env python3

from pyxdc import HTTP_PROVIDER
from pyxdc.wallet import Wallet
from pyxdc.utils import amount_unit_converter

import json

# XinFin xprivate key
XPRIVATE_KEY: str = "xprvA3w9Gn8BTtGrCH9mA5MuYVJ3iR8Zi1cig5hXwpKiL98veDnhouT2hEE3wDTWEhofWx" \
                    "Hu59DRaeh7yC4VEJUTz2Tb9GjFkxJK9gMQSPKYnwT"

# Initialize XinFin mainnet Wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin Wallet from xprivate key
wallet.from_xprivate_key(xprivate_key=XPRIVATE_KEY)

# Print all XinFin Wallet information's
# print(json.dumps(wallet.dumps(), indent=4, ensure_ascii=False))

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
