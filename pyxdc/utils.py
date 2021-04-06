#!/usr/bin/env python3

from mnemonic import Mnemonic
from web3 import Web3
from binascii import (
    hexlify, unhexlify
)
from random import choice
from string import (
    ascii_letters, digits
)
from typing import (
    AnyStr, Optional, Union
)

import os
import unicodedata
import binascii

from .exceptions import (
    UnitError, AddressError
)
from .libs.base58 import check_decode
from .config import config

# Alphabet and digits.
letters: str = ascii_letters + digits
# XinFin configuration
config: dict = config


def __unhexlify__(integer: int) -> bytes:
    try:
        return unhexlify("0%x" % integer)
    except binascii.Error:
        return unhexlify("%x" % integer)


def get_bytes(string: AnyStr) -> bytes:
    if isinstance(string, bytes):
        byte = string
    elif isinstance(string, str):
        byte = bytes.fromhex(string)
    else:
        raise TypeError("Agreement must be either 'bytes' or 'string'!")
    return byte


def generate_passphrase(length: int = 32) -> str:
    """
    Generate entropy hex string.

    :param length: Passphrase length, default to 32.
    :type length: int

    :returns: str -- Passphrase hex string.

    >>> from pyxdc.utils import generate_passphrase
    >>> generate_passphrase(length=32)
    "N39rPfa3QvF2Tm2nPyoBpXNiBFXJywTz"
    """

    return str().join(choice(letters) for _ in range(length))


def generate_entropy(strength: int = 128) -> str:
    """
    Generate entropy hex string.

    :param strength: Entropy strength, default to 128.
    :type strength: int

    :returns: str -- Entropy hex string.

    >>> from pyxdc.utils import generate_entropy
    >>> generate_entropy(strength=128)
    "ee535b143b0d9d1f87546f9df0d06b1a"
    """

    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "Strength should be one of the following "
            "[128, 160, 192, 224, 256], but it is not (%d)."
            % strength
        )
    return hexlify(os.urandom(strength // 8)).decode()


def generate_mnemonic(language: str = "english", strength: int = 128) -> str:
    """
    Generate mnemonic words.

    :param language: Mnemonic language, default to english.
    :type language: str
    :param strength: Entropy strength, default to 128.
    :type strength: int

    :returns: str -- Mnemonic words.

    >>> from pyxdc.utils import generate_mnemonic
    >>> generate_mnemonic(language="french")
    "sceptre capter séquence girafe absolu relatif fleur zoologie muscle sirop saboter parure"
    """

    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "Strength should be one of the following "
            "[128, 160, 192, 224, 256], but it is not (%d)."
            % strength
        )

    return Mnemonic(language=language).generate(strength=strength)


def is_entropy(entropy: str) -> bool:
    """
    Check entropy hex string.

    :param entropy: Mnemonic words.
    :type entropy: str

    :returns: bool -- Entropy valid/invalid.

    >>> from pyxdc.utils import is_entropy
    >>> is_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
    True
    """

    return len(unhexlify(entropy)) in [16, 20, 24, 28, 32]


def is_mnemonic(mnemonic: str, language: Optional[str] = None) -> bool:
    """
    Check mnemonic words.

    :param mnemonic: Mnemonic words.
    :type mnemonic: str
    :param language: Mnemonic language, default to None.
    :type language: str

    :returns: bool -- Mnemonic valid/invalid.

    >>> from pyxdc.utils import is_mnemonic
    >>> is_mnemonic(mnemonic="sceptre capter séquence girafe absolu relatif fleur zoologie muscle sirop saboter parure")
    True
    """

    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")
    try:
        mnemonic = unicodedata.normalize("NFKD", mnemonic)
        if language is None:
            for _language in ["english", "french", "italian",
                              "chinese_simplified", "chinese_traditional", "japanese", "korean", "spanish"]:
                valid = False
                if Mnemonic(language=_language).check(mnemonic=mnemonic) is True:
                    valid = True
                    break
            return valid
        else:
            return Mnemonic(language=language).check(mnemonic=mnemonic)
    except:
        return False
    
    
def is_address(address: str) -> bool:
    """
    Check XinFin address.
    
    :param address: XinFin address.
    :type address: str

    :returns: bool -- XinFin valid/invalid address.
    
    >>> from pyxdc.utils import is_address
    >>> is_address(address="xdc1ee11011ae12103a488a82dc33e03f337bc93ba7")
    True
    """

    if not isinstance(address, str):
        raise TypeError("Address must be string format")
    elif address.startswith("xdc"):
        return Web3.isAddress(f"0x{address.lstrip('xdc')}")
    elif address.startswith("0x"):
        return Web3.isAddress(address)
    return False


def is_checksum_address(address: str) -> bool:
    """
    Check XinFin checksum address.

    :param address: XinFin address.
    :type address: str

    :returns: bool -- XinFin valid/invalid checksum address.

    >>> from pyxdc.utils import is_checksum_address
    >>> is_checksum_address(address="xdc1ee11011ae12103a488a82dc33e03f337bc93ba7")
    False
    >>> is_checksum_address(address="xdc1Ee11011ae12103a488A82DC33e03f337Bc93ba7")
    True
    """

    if not isinstance(address, str):
        raise TypeError("Address must be string format")
    elif address.startswith("xdc"):
        return Web3.isChecksumAddress(f"0x{address.lstrip('xdc')}")
    elif address.startswith("0x"):
        return Web3.isAddress(address)
    return False


def to_checksum_address(address: str, prefix: str = "xdc") -> str:
    """
    To XinFin checksum address.

    :param address: XinFin address.
    :type address: str
    :param prefix: XinFin address prefix, default to xdc.
    :type prefix: str

    :returns: str -- XinFin checksum address.

    >>> from pyxdc.utils import is_checksum_address
    >>> is_checksum_address(address="xdc1ee11011ae12103a488a82dc33e03f337bc93ba7")
    "xdc1Ee11011ae12103a488A82DC33e03f337Bc93ba7"
    """

    if not is_address(address):
        raise AddressError("Invalid XinFin address.")

    if address.startswith("xdc"):
        checksum_address: str = Web3.toChecksumAddress(f"0x{address.lstrip('xdc')}")
    elif address.startswith("0x"):
        checksum_address: str = Web3.toChecksumAddress(address)
    else:
        raise AddressError("Invalid XinFin address prefix.")

    if prefix == "xdc":
        return f"xdc{checksum_address.lstrip('0x')}"
    elif prefix == "0x":
        return checksum_address
    raise AddressError("Invalid XinFin address prefix.")


def get_entropy_strength(entropy: str) -> int:
    """
    Get entropy strength.

    :param entropy: Entropy hex string.
    :type entropy: str

    :returns: int -- Entropy strength.

    >>> from pyxdc.utils import get_entropy_strength
    >>> get_entropy_strength(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
    128
    """

    if not is_entropy(entropy=entropy):
        raise ValueError("Invalid entropy hex string.")

    length = len(unhexlify(entropy))
    if length == 16:
        return 128
    elif length == 20:
        return 160
    elif length == 24:
        return 192
    elif length == 28:
        return 224
    elif length == 32:
        return 256


def get_mnemonic_strength(mnemonic: str, language: Optional[str] = None) -> int:
    """
    Get mnemonic strength.

    :param mnemonic: Mnemonic words.
    :type mnemonic: str
    :param language: Mnemonic language, default to None.
    :type language: str

    :returns: int -- Mnemonic strength.

    >>> from pyxdc.utils import get_mnemonic_strength
    >>> get_mnemonic_strength(mnemonic="sceptre capter séquence girafe absolu relatif fleur zoologie muscle sirop saboter parure")
    128
    """

    if not is_mnemonic(mnemonic=mnemonic, language=language):
        raise ValueError("Invalid mnemonic words.")

    words = len(unicodedata.normalize("NFKD", mnemonic).split(" "))
    if words == 12:
        return 128
    elif words == 15:
        return 160
    elif words == 18:
        return 192
    elif words == 21:
        return 224
    elif words == 24:
        return 256


def get_mnemonic_language(mnemonic: str) -> str:
    """
    Get mnemonic language.

    :param mnemonic: Mnemonic words.
    :type mnemonic: str

    :returns: str -- Mnemonic language.

    >>> from pyxdc.utils import get_mnemonic_language
    >>> get_mnemonic_language(mnemonic="sceptre capter séquence girafe absolu relatif fleur zoologie muscle sirop saboter parure")
    "french"
    """

    if not is_mnemonic(mnemonic=mnemonic):
        raise ValueError("Invalid mnemonic words.")

    language = None
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    for _language in ["english", "french", "italian",
                      "chinese_simplified", "chinese_traditional", "japanese", "korean", "spanish"]:
        if Mnemonic(language=_language).check(mnemonic=mnemonic) is True:
            language = _language
            break
    return language


def entropy_to_mnemonic(entropy: str, language: str = "english") -> str:
    """
    Get mnemonic from entropy hex string.

    :param entropy: Entropy hex string.
    :type entropy: str
    :param language: Mnemonic language, default to english.
    :type language: str

    :returns: str -- Mnemonic words.

    >>> from pyxdc.utils import entropy_to_mnemonic
    >>> entropy_to_mnemonic(entropy="ee535b143b0d9d1f87546f9df0d06b1a", language="korean")
    "학력 외침 주민 스위치 출연 연습 근본 여전히 울음 액수 귀신 마누라"
    """

    if not is_entropy(entropy=entropy):
        raise ValueError("Invalid entropy hex string.")

    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("Invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")

    return Mnemonic(language=language).to_mnemonic(unhexlify(entropy))


def mnemonic_to_entropy(mnemonic: str, language: Optional[str] = None) -> str:
    """
    Get entropy from mnemonic words.

    :param mnemonic: Mnemonic words.
    :type mnemonic: str
    :param language: Mnemonic language, default to english.
    :type language: str

    :returns: str -- Enropy hex string.

    >>> from pyxdc.utils import mnemonic_to_entropy
    >>> mnemonic_to_entropy(mnemonic="학력 외침 주민 스위치 출연 연습 근본 여전히 울음 액수 귀신 마누라", language="korean")
    "ee535b143b0d9d1f87546f9df0d06b1a"
    """

    if not is_mnemonic(mnemonic=mnemonic, language=language):
        raise ValueError("Invalid mnemonic words.")

    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    language = language if language else get_mnemonic_language(mnemonic=mnemonic)
    return Mnemonic(language=language).to_entropy(mnemonic).hex()


def is_root_xprivate_key(xprivate_key: str) -> bool:

    decoded_xprivate_key = check_decode(xprivate_key).hex()
    if len(decoded_xprivate_key) != 156:  # 78
        raise ValueError("Invalid XPrivate Key.")
    version = config["extended_private_key"]
    raw = f"{__unhexlify__(version).hex()}000000000000000000"
    return decoded_xprivate_key.startswith(raw)


def is_root_xpublic_key(xpublic_key: str) -> bool:

    decoded_xpublic_key = check_decode(xpublic_key).hex()
    if len(decoded_xpublic_key) != 156:  # 78
        raise ValueError("Invalid XPublic Key.")
    version = config["extended_public_key"]
    raw = f"{__unhexlify__(version).hex()}000000000000000000"
    return decoded_xpublic_key.startswith(raw)


def amount_unit_converter(amount: Union[int, float], unit: str = "Wei2XDC") -> Union[int, float]:
    """
    XinFin amount unit converter.

    :param amount: XinFIn amount.
    :type amount: int, float
    :param unit: XinFIn unit, default to Wei2XDC
    :type unit: str

    :returns: int, float -- XinFin amount.

    >>> from pyxdc.utils import amount_unit_converter
    >>> amount_unit_converter(amount=100_000_000, unit="Wei2XDC")
    0.1
    """

    if unit not in ["XDC2Gwei", "XDC2Wei", "Gwei2XDC", "Gwei2Wei", "Wei2XDC", "Wei2Gwei"]:
        raise UnitError(f"Invalid '{unit}' unit/type", 
                        "choose only 'XDC2Gwei', 'XDC2Wei', 'Gwei2XDC', 'Gwei2Wei', 'Wei2XDC' or 'Wei2Gwei' units.")

    # Constant values
    XDC, Gwei, Wei = (
        config["units"]["XDC"],
        config["units"]["Gwei"],
        config["units"]["Wei"]
    )

    if unit == "XDC2Gwei":
        return float((amount * Gwei) / XDC)
    elif unit == "XDC2Wei":
        return int((amount * Wei) / XDC)
    elif unit == "Gwei2XDC":
        return float((amount * XDC) / Gwei)
    elif unit == "Gwei2Wei":
        return int((amount * Wei) / Gwei)
    elif unit == "Wei2XDC":
        return float((amount * XDC) / Wei)
    elif unit == "Wei2Gwei":
        return int((amount * Gwei) / Wei)
