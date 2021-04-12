#!/usr/bin/env python3

from pyxdc import HTTP_PROVIDER
from pyxdc.wallet import Wallet
from pyxdc.utils import (
    generate_mnemonic, amount_unit_converter, is_mnemonic
)
from typing import Optional

import json

# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 256  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "chinese_simplified"  # Default is english
# Generate new mnemonic words
MNEMONIC: str = generate_mnemonic(language=LANGUAGE, strength=STRENGTH)
# Secret passphrase for mnemonic words
PASSPHRASE: Optional[str] = None  # str("meherett")

# Check mnemonic words
assert is_mnemonic(mnemonic=MNEMONIC, language=LANGUAGE)

# Initialize XinFin mainnet Wallet
wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
# Get XinFin Wallet from mnemonic words
wallet.from_mnemonic(
    mnemonic=MNEMONIC, passphrase=PASSPHRASE, language=LANGUAGE
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
print("Balance:", amount_unit_converter(amount=wallet.balance(), unit="Wei2XDC"), "XDC")

print("-------- Sign & Verify --------")

MESSAGE: str = "1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"

print("Message:", MESSAGE)
signature: str = wallet.sign(message=MESSAGE)
print("Signature:", signature)
print("Verified:", wallet.verify(message=MESSAGE, signature=signature))
