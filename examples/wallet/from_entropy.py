#!/usr/bin/env python3

from pyxdc import Wallet
from pyxdc.providers import HTTP_PROVIDER
from pyxdc.utils import generate_entropy
from typing import Optional

import json

# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 160  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "english"  # Default is english
# Generate new entropy hex string
ENTROPY: str = "b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e"  # generate_entropy(strength=STRENGTH)
# Secret passphrase for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"

# Initialize XinFin mainnet Wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin Wallet from entropy
wallet.from_entropy(
    entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
)

# Derivation from path
# wallet.from_path("m/44'/550'/0'/0/0")
# Or derivation from index
wallet.from_index(44, hardened=True)
wallet.from_index(550, hardened=True)
wallet.from_index(0, hardened=True)
wallet.from_index(0)
wallet.from_index(0)

# Print all XinFin Wallet information's
# print(json.dumps(wallet.dumps(), indent=4, ensure_ascii=False))

print("Strength:", wallet.strength())
print("Entropy:", wallet.entropy())
print("Mnemonic:", wallet.mnemonic())
print("Language:", wallet.language())
print("Passphrase:", wallet.passphrase())
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
print("Balance:", wallet.balance())

print("-------- Sign & Verify --------")

MESSAGE: str = "1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"

print("Message:", MESSAGE)
signature: str = wallet.sign(message=MESSAGE)
print("Signature:", signature)
print("Verified:", wallet.verify(message=MESSAGE, signature=signature))