#!/usr/bin/env python3

from pyxdc import (
    HTTP_PROVIDER, DEFAULT_PATH
)
from pyxdc.transaction import NormalTransaction
from pyxdc.rpc import submit_transaction_raw
from pyxdc.wallet import Wallet
from pyxdc.utils import (
    amount_unit_converter, to_checksum_address
)

import json

# Wallet entropy hex string
ENTROPY: str = "b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e"
# Recipient XinFin address
RECIPIENT_ADDRESS: str = to_checksum_address("xdcAF78a3fc5FEf31F374910873D9A8fc70d2F193f8")
# Received value (Wei unit)
VALUE: int = amount_unit_converter(amount=1, unit="XDC2Wei")

# Initialize XinFin wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin wallet from entropy
wallet.from_entropy(entropy=ENTROPY, language="english")
# Derivation from default path
wallet.from_path(path=DEFAULT_PATH)

print("From Wallet Balance:", wallet.balance(unit="XDC"), "XDC")

# Initialize normal transaction
normal_transaction: NormalTransaction = NormalTransaction(provider=HTTP_PROVIDER)
# Build normal transaction
normal_transaction.build_transaction(
    address=wallet.address(), recipient=RECIPIENT_ADDRESS, value=VALUE, estimate_gas=True
)
# Sing normal transaction by private key
normal_transaction.sign_transaction(
    private_key=wallet.private_key()
)

print("Normal Transaction Fee:", normal_transaction.fee(unit="Wei"), "Wei")
print("Normal Transaction Hash:", normal_transaction.hash())
print("Normal Transaction Raw:", normal_transaction.raw())
print("Normal Transaction Json:", json.dumps(normal_transaction.json(), indent=4))

# Submit normal transaction raw
# print("\nSubmitted Normal Transaction Hash:", submit_transaction_raw(
#     transaction_raw=normal_transaction.raw(), provider=HTTP_PROVIDER
# ))
