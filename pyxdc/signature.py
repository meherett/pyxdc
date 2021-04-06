#!/usr/bin/env python3

from binascii import (
    hexlify, unhexlify
)

import ecdsa


def sign(private_key: str, message: str) -> str:
    """
    Sign XinFin message data by private key.
    
    :param private_key: XinFin private key.
    :type private_key: str.
    :param message: Message data.
    :type message: str.
    
    :return: str -- XinFin signed message or signature.
    
    >>> from pyxdc.signature import sign
    >>> sign(private_key="4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de", message="1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6")
    "2a6f2584b6d20f06c23c9e12248f9fdd5d17d1fe973ea2485050b082c35030495a598e2aa1af37d9672db51c6700e6bbc7c2a33b6a1f4eac92d8500cc161affe"
    """

    signing_key: ecdsa.SigningKey = ecdsa.SigningKey.from_string(
        unhexlify(private_key), curve=ecdsa.SECP256k1
    )
    signature: bytes = signing_key.sign(message.encode())
    return hexlify(signature).decode()


def verify(public_key: str, message: str, signature: str) -> bool:
    """
    Verify XinFin signature by public key.
    
    :param public_key: XinFin public key.
    :type public_key: str.
    :param message: Message data.
    :type message: str.
    :param signature: Signed message data.
    :type signature: str.
    
    :return: bool -- Verified signature.
    
    >>> from pyxdc.signature import verify
    >>> verify(public_key="03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85", message="1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6", signature="2a6f2584b6d20f06c23c9e12248f9fdd5d17d1fe973ea2485050b082c35030495a598e2aa1af37d9672db51c6700e6bbc7c2a33b6a1f4eac92d8500cc161affe")
    True
    """

    result: bool = False
    verifying_key: ecdsa.VerifyingKey = ecdsa.VerifyingKey.from_string(
        unhexlify(public_key), curve=ecdsa.SECP256k1
    )
    try:
        result = verifying_key.verify(
            unhexlify(signature), message.encode()
        )
    except ecdsa.BadSignatureError:
        result = False
    return result
