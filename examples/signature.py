# !/usr/bin/env python3

from pyxdc.signature import sign, verify

# XinFin private key
PRIVATE_KEY: str = "a563a95a3a098081e1942c6bfe7a5297248fe73606e351a74d62349eba581522"
# XinFin public key
PUBLIC_KEY: str = "02ffa317c125ce8993d388b5c230e267558bf8d86425b1d80012c5a61e29572cb2"

# Message data
MESSAGE: str = "Hello Meheret :)"
print("Message:", MESSAGE)
# Sign message by private key
signature: str = sign(private_key=PRIVATE_KEY, message=MESSAGE)
print("Signature:", signature)
# Verify signature by public key
verified: bool = verify(public_key=PUBLIC_KEY, signature=signature, message=MESSAGE)
print("Verified:", verified)

# Message data hash
MESSAGE_HASH: str = "34482808c8f9e9c78b9ba295438160cc5f1cc24d5bfd992aaef0602319cb379b"
print("Message Hash:", MESSAGE_HASH)
# Sign message by private key
signature: str = sign(private_key=PRIVATE_KEY, message_hash=MESSAGE_HASH)
print("Signature:", signature)
# Verify signature by public key
verified: bool = verify(public_key=PUBLIC_KEY, signature=signature, message_hash=MESSAGE_HASH)
print("Verified:", verified)
