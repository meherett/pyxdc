#!/usr/bin/env python3

from binascii import (
    hexlify, unhexlify
)
from sha3 import keccak_256

import hmac
import hashlib


from typing import (
    Any, Callable, Optional, Tuple
)
from eth_keys.utils.padding import pad32
from eth_utils import (
    big_endian_to_int, int_to_big_endian, curried
)
from eth_keys.validation import (
    validate_recoverable_signature_bytes,
    validate_compressed_public_key_bytes
)
from eth_keys.utils.numeric import (
    int_to_byte,
)

from eth_keys.constants import (
    SECPK1_N as N,
    SECPK1_G as G,
    SECPK1_P as P,
    SECPK1_A as A,
    SECPK1_B as B
)


def inv(a: int, n: int) -> int:
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def to_jacobian(p: Tuple[int, int]) -> Tuple[int, int, int]:
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p: Tuple[int, int, int]) -> Tuple[int, int, int]:
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)


def jacobian_add(p: Tuple[int, int, int],
                 q: Tuple[int, int, int]) -> Tuple[int, int, int]:
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)


def from_jacobian(p: Tuple[int, int, int]) -> Tuple[int, int]:
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)


def jacobian_multiply(a: Tuple[int, int, int],
                      n: int) -> Tuple[int, int, int]:
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n // 2))
    elif (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n // 2)), a)
    else:
        raise Exception("Invariant: Unreachable code path")


def fast_multiply(a: Tuple[int, int],
                  n: int) -> Tuple[int, int]:
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def fast_add(a: Tuple[int, int],
             b: Tuple[int, int]) -> Tuple[int, int]:
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))


def decode_public_key(public_key_bytes: bytes) -> Tuple[int, int]:
    left = big_endian_to_int(public_key_bytes[0:32])
    right = big_endian_to_int(public_key_bytes[32:64])
    return left, right


def deterministic_generate_k(msg_hash: bytes,
                             private_key_bytes: bytes,
                             digest_fn: Callable[[], Any] = hashlib.sha256) -> int:
    v_0 = b'\x01' * 32
    k_0 = b'\x00' * 32

    k_1 = hmac.new(k_0, v_0 + b'\x00' + private_key_bytes + msg_hash, digest_fn).digest()
    v_1 = hmac.new(k_1, v_0, digest_fn).digest()
    k_2 = hmac.new(k_1, v_1 + b'\x01' + private_key_bytes + msg_hash, digest_fn).digest()
    v_2 = hmac.new(k_2, v_1, digest_fn).digest()

    kb = hmac.new(k_2, v_2, digest_fn).digest()
    k = big_endian_to_int(kb)
    return k


def to_bytes(vrs: Tuple[int, int, int]) -> bytes:
    vb = int_to_byte(vrs[0])
    rb = pad32(int_to_big_endian(vrs[1]))
    sb = pad32(int_to_big_endian(vrs[2]))
    return b''.join((rb, sb, vb))


def ecdsa_raw_sign(msg_hash: bytes,
                   private_key_bytes: bytes) -> bytes:
    z = big_endian_to_int(msg_hash)
    k = deterministic_generate_k(msg_hash, private_key_bytes)

    r, y = fast_multiply(G, k)
    s_raw = inv(k, N) * (z + r * big_endian_to_int(private_key_bytes)) % N

    v = 27 + ((y % 2) ^ (0 if s_raw * 2 < N else 1))
    s = s_raw if s_raw * 2 < N else N - s_raw

    return to_bytes(vrs=(v - 27, r, s))


def ecdsa_raw_verify(msg_hash: bytes,
                     rs: Tuple[int, int],
                     public_key_bytes: bytes) -> bool:
    raw_public_key = decode_public_key(public_key_bytes)

    r, s = rs

    w = inv(s, N)
    z = big_endian_to_int(msg_hash)

    u1, u2 = z * w % N, r * w % N
    x, y = fast_add(
        fast_multiply(G, u1),
        fast_multiply(raw_public_key, u2),
    )
    return bool(r == x and (r % N) and (s % N))


def encode_raw_public_key(raw_public_key: Tuple[int, int]) -> bytes:
    left, right = raw_public_key
    return b''.join((
        pad32(int_to_big_endian(left)),
        pad32(int_to_big_endian(right)),
    ))


def compress_public_key(uncompressed_public_key_bytes: bytes) -> bytes:
    x, y = decode_public_key(uncompressed_public_key_bytes)
    if y % 2 == 0:
        prefix = b"\x02"
    else:
        prefix = b"\x03"
    return prefix + pad32(int_to_big_endian(x))


def decompress_public_key(compressed_public_key_bytes: bytes) -> bytes:
    if len(compressed_public_key_bytes) != 33:
        raise ValueError("Invalid compressed public key")

    prefix = compressed_public_key_bytes[0]
    if prefix not in (2, 3):
        raise ValueError("Invalid compressed public key")

    x = big_endian_to_int(compressed_public_key_bytes[1:])
    y_squared = (x**3 + A * x + B) % P
    y_abs = pow(y_squared, ((P + 1) // 4), P)

    if (prefix == 2 and y_abs & 1 == 1) or (prefix == 3 and y_abs & 1 == 0):
        y = (-y_abs) % P
    else:
        y = y_abs

    return encode_raw_public_key((x, y))


def sign(private_key: str, message: Optional[str] = None, message_hash: Optional[str] = None) -> str:
    """
    Sign XinFin message data by private key.

    :param private_key: XinFin private key.
    :type private_key: str.
    :param message: Message data, default to ``None``.
    :type message: str.
    :param message_hash: Message data hash, default to ``None``.
    :type message_hash: str.

    :return: str -- XinFin signed message or signature.

    >>> from pyxdc.signature import sign
    >>> sign(private_key="4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de", message="meherett")
    "74ad07a84b87fa3efa2f0e825506fb8bbee41021ca77a30e8ffa2bd66d47d99917d4a0587185e78a051a9cb80ebf65c7d62dbeedb7f9a029f961d70b52a10dc001"
    >>> sign(private_key="4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de", message_hash="4bbbfd0c33fea618f4a9aa75c02fe76e50fa59798af021bc34f7856f3259c685")
    "74ad07a84b87fa3efa2f0e825506fb8bbee41021ca77a30e8ffa2bd66d47d99917d4a0587185e78a051a9cb80ebf65c7d62dbeedb7f9a029f961d70b52a10dc001"
    """

    if message:
        message_bytes = curried.to_bytes(primitive=None, hexstr=None, text=message)
        msg_length = str(len(message_bytes)).encode('utf-8')
        joined = b'\x19' + b'E' + b'thereum Signed Message:\n' + msg_length + message_bytes
        keccak_256_message = keccak_256()
        keccak_256_message.update(joined)
        message_hash = keccak_256_message.digest()
    elif message_hash:
        message_hash = unhexlify(message_hash)
    else:
        raise ValueError("Message data or hash is required to sign.")

    return ecdsa_raw_sign(
        msg_hash=message_hash, private_key_bytes=unhexlify(private_key)
    ).hex()


def verify(public_key: str, signature: str, message: Optional[str] = None, message_hash: Optional[str] = None) -> bool:
    """
    Verify XinFin signature by public key.

    :param public_key: XinFin public key.
    :type public_key: str.
    :param signature: Signed message data.
    :type signature: str.
    :param message: Message data, default to ``None``.
    :type message: str.
    :param message_hash: Message data hash, default to ``None``.
    :type message_hash: str.

    :return: bool -- Verified signature.

    >>> from pyxdc.signature import verify
    >>> verify(public_key="03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85", message="meherett", signature="74ad07a84b87fa3efa2f0e825506fb8bbee41021ca77a30e8ffa2bd66d47d99917d4a0587185e78a051a9cb80ebf65c7d62dbeedb7f9a029f961d70b52a10dc001")
    True
    >>> verify(public_key="03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85", message_hash="4bbbfd0c33fea618f4a9aa75c02fe76e50fa59798af021bc34f7856f3259c685", signature="74ad07a84b87fa3efa2f0e825506fb8bbee41021ca77a30e8ffa2bd66d47d99917d4a0587185e78a051a9cb80ebf65c7d62dbeedb7f9a029f961d70b52a10dc001")
    True
    """

    if message:
        message_bytes = curried.to_bytes(primitive=None, hexstr=None, text=message)
        msg_length = str(len(message_bytes)).encode('utf-8')
        joined = b'\x19' + b'E' + b'thereum Signed Message:\n' + msg_length + message_bytes
        keccak_256_message = keccak_256()
        keccak_256_message.update(joined)
        message_hash = keccak_256_message.digest()
    elif message_hash:
        message_hash = unhexlify(message_hash)
    else:
        raise ValueError("Message data or hash is required to sign.")

    signature = unhexlify(signature)
    validate_recoverable_signature_bytes(signature)
    r = big_endian_to_int(signature[0:32])
    s = big_endian_to_int(signature[32:64])
    v = ord(signature[64:65])
    validate_compressed_public_key_bytes(unhexlify(public_key))
    uncompressed_public_key = decompress_public_key(unhexlify(public_key))

    return ecdsa_raw_verify(
        msg_hash=message_hash, rs=(r, s), public_key_bytes=uncompressed_public_key
    )
