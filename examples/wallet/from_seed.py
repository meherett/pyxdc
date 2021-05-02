#!/usr/bin/env python3

from pyxdc import HTTP_PROVIDER
from pyxdc.wallet import Wallet
from pyxdc.utils import amount_unit_converter

import json

# Wallet seed
SEED: str = "b3337a2fe409afbb257b504e4c09d36b57c32c452b71a0ed413298a5172f727a06bf6605488" \
            "723bc545a4bd51f5cd29a3e8bd1433bd1d26e6bf866ff53d1493f"

# Initialize XinFin mainnet Wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin Wallet from seed
wallet.from_seed(seed=SEED)

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

print("Seed:", wallet.seed())
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
