#!/usr/bin/env python3

from mnemonic import Mnemonic
from web3 import Web3
from web3.auto import w3
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
from eth_typing import HexStr
from eth_utils import (
    keccak, to_bytes
)
from rlp.sedes import (
    Binary, big_endian_int, binary
)

import os
import rlp
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
        return Web3.isAddress(f"0x{address.replace('xdc', '', 1)}")
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
        return Web3.isChecksumAddress(f"0x{address.replace('xdc', '', 1)}")
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
        checksum_address: str = Web3.toChecksumAddress(f"0x{address.replace('xdc', '', 1)}")
    elif address.startswith("0x"):
        checksum_address: str = Web3.toChecksumAddress(address)
    else:
        raise AddressError("Invalid XinFin address prefix.")

    if prefix == "xdc":
        return f"xdc{checksum_address.lstrip('0x')}"
    elif prefix == "0x":
        return checksum_address
    raise AddressError("Invalid XinFin address prefix.")


def decode_transaction_raw(transaction_raw: str) -> dict:
    """
    Decode XinFin transaction raw.

    :param transaction_raw: XinFin transaction raw.
    :type transaction_raw: str

    :returns: dict -- XinFin decoded transaction.

    >>> from pyxdc.utils import decode_transaction_raw
    >>> decode_transaction_raw(transaction_raw="0xf90703058504a817c800831e84808080b906b0608060405234801561001057600080fd5b506040518060400160405280600581526020017f48656c6c6f0000000000000000000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50610166565b82805461006e90610105565b90600052602060002090601f01602090048101928261009057600085556100d7565b82601f106100a957805160ff19168380011785556100d7565b828001600101855582156100d7579182015b828111156100d65782518255916020019190600101906100bb565b5b5090506100e491906100e8565b5090565b5b808211156101015760008160009055506001016100e9565b5090565b6000600282049050600182168061011d57607f821691505b6020821081141561013157610130610137565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b61053b806101756000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063a413686214610046578063cfae321714610062578063ef690cc014610080575b600080fd5b610060600480360381019061005b91906102e3565b61009e565b005b61006a6100b8565b604051610077919061035d565b60405180910390f35b61008861014a565b604051610095919061035d565b60405180910390f35b80600090805190602001906100b49291906101d8565b5050565b6060600080546100c790610433565b80601f01602080910402602001604051908101604052809291908181526020018280546100f390610433565b80156101405780601f1061011557610100808354040283529160200191610140565b820191906000526020600020905b81548152906001019060200180831161012357829003601f168201915b5050505050905090565b6000805461015790610433565b80601f016020809104026020016040519081016040528092919081815260200182805461018390610433565b80156101d05780601f106101a5576101008083540402835291602001916101d0565b820191906000526020600020905b8154815290600101906020018083116101b357829003601f168201915b505050505081565b8280546101e490610433565b90600052602060002090601f016020900481019282610206576000855561024d565b82601f1061021f57805160ff191683800117855561024d565b8280016001018555821561024d579182015b8281111561024c578251825591602001919060010190610231565b5b50905061025a919061025e565b5090565b5b8082111561027757600081600090555060010161025f565b5090565b600061028e610289846103a4565b61037f565b9050828152602081018484840111156102a657600080fd5b6102b18482856103f1565b509392505050565b600082601f8301126102ca57600080fd5b81356102da84826020860161027b565b91505092915050565b6000602082840312156102f557600080fd5b600082013567ffffffffffffffff81111561030f57600080fd5b61031b848285016102b9565b91505092915050565b600061032f826103d5565b61033981856103e0565b9350610349818560208601610400565b610352816104f4565b840191505092915050565b600060208201905081810360008301526103778184610324565b905092915050565b600061038961039a565b90506103958282610465565b919050565b6000604051905090565b600067ffffffffffffffff8211156103bf576103be6104c5565b5b6103c8826104f4565b9050602081019050919050565b600081519050919050565b600082825260208201905092915050565b82818337600083830152505050565b60005b8381101561041e578082015181840152602081019050610403565b8381111561042d576000848401525b50505050565b6000600282049050600182168061044b57607f821691505b6020821081141561045f5761045e610496565b5b50919050565b61046e826104f4565b810181811067ffffffffffffffff8211171561048d5761048c6104c5565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f830116905091905056fea264697066735822122002786b5114bea14354170503b8bffe80a17bb5e4610cb41deca549935965f30864736f6c634300080300331ca0f2704e20656acf4b067c23ff6e7e2bf8e9b6f75383c408607fce7f90ef39aedba07612be142f5202b3970ee9b4c821bd95df4eb007735acc9c145b0d204d697f8c")
    {'hash': '0x57232e7e3f0e4f5f49cad5074bea10c98ee18efd4371e15c163560b8bc8ebb40', 'from': '0x68bF25F60508C2820d3D72E1806503F0955eFf94', 'to': None, 'nonce': 5, 'gas': 2000000, 'gas_price': 20000000000, 'value': 0, 'data': '0x608060405234801561001057600080fd5b506040518060400160405280600581526020017f48656c6c6f0000000000000000000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50610166565b82805461006e90610105565b90600052602060002090601f01602090048101928261009057600085556100d7565b82601f106100a957805160ff19168380011785556100d7565b828001600101855582156100d7579182015b828111156100d65782518255916020019190600101906100bb565b5b5090506100e491906100e8565b5090565b5b808211156101015760008160009055506001016100e9565b5090565b6000600282049050600182168061011d57607f821691505b6020821081141561013157610130610137565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b61053b806101756000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063a413686214610046578063cfae321714610062578063ef690cc014610080575b600080fd5b610060600480360381019061005b91906102e3565b61009e565b005b61006a6100b8565b604051610077919061035d565b60405180910390f35b61008861014a565b604051610095919061035d565b60405180910390f35b80600090805190602001906100b49291906101d8565b5050565b6060600080546100c790610433565b80601f01602080910402602001604051908101604052809291908181526020018280546100f390610433565b80156101405780601f1061011557610100808354040283529160200191610140565b820191906000526020600020905b81548152906001019060200180831161012357829003601f168201915b5050505050905090565b6000805461015790610433565b80601f016020809104026020016040519081016040528092919081815260200182805461018390610433565b80156101d05780601f106101a5576101008083540402835291602001916101d0565b820191906000526020600020905b8154815290600101906020018083116101b357829003601f168201915b505050505081565b8280546101e490610433565b90600052602060002090601f016020900481019282610206576000855561024d565b82601f1061021f57805160ff191683800117855561024d565b8280016001018555821561024d579182015b8281111561024c578251825591602001919060010190610231565b5b50905061025a919061025e565b5090565b5b8082111561027757600081600090555060010161025f565b5090565b600061028e610289846103a4565b61037f565b9050828152602081018484840111156102a657600080fd5b6102b18482856103f1565b509392505050565b600082601f8301126102ca57600080fd5b81356102da84826020860161027b565b91505092915050565b6000602082840312156102f557600080fd5b600082013567ffffffffffffffff81111561030f57600080fd5b61031b848285016102b9565b91505092915050565b600061032f826103d5565b61033981856103e0565b9350610349818560208601610400565b610352816104f4565b840191505092915050565b600060208201905081810360008301526103778184610324565b905092915050565b600061038961039a565b90506103958282610465565b919050565b6000604051905090565b600067ffffffffffffffff8211156103bf576103be6104c5565b5b6103c8826104f4565b9050602081019050919050565b600081519050919050565b600082825260208201905092915050565b82818337600083830152505050565b60005b8381101561041e578082015181840152602081019050610403565b8381111561042d576000848401525b50505050565b6000600282049050600182168061044b57607f821691505b6020821081141561045f5761045e610496565b5b50919050565b61046e826104f4565b810181811067ffffffffffffffff8211171561048d5761048c6104c5565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f830116905091905056fea264697066735822122002786b5114bea14354170503b8bffe80a17bb5e4610cb41deca549935965f30864736f6c63430008030033', 'chain_id': -4, 'r': '0xf2704e20656acf4b067c23ff6e7e2bf8e9b6f75383c408607fce7f90ef39aedb', 's': '0x7612be142f5202b3970ee9b4c821bd95df4eb007735acc9c145b0d204d697f8c', 'v': 28}
    """

    class Transaction(rlp.Serializable):
        fields: list = [
            ("nonce", big_endian_int),
            ("gas_price", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("v", big_endian_int),
            ("r", big_endian_int),
            ("s", big_endian_int),
        ]

    def hex_to_bytes(data: str) -> bytes:
        return to_bytes(hexstr=HexStr(data))

    transaction = rlp.decode(hex_to_bytes(transaction_raw), Transaction)
    decoded_transaction: dict = {
        "hash": Web3.toHex(keccak(hex_to_bytes(transaction_raw))),
        "from": w3.eth.account.recover_transaction(transaction_raw),
        "to": (w3.toChecksumAddress(transaction.to) if transaction.to else None),
        "nonce": transaction.nonce,
        "gas": transaction.gas,
        "gas_price": transaction.gas_price,
        "value": transaction.value,
        "data": w3.toHex(transaction.data),
        "chain_id": ((transaction.v - 35) // 2 if transaction.v % 2 else (transaction.v - 36) // 2),
        "r": hex(transaction.r),
        "s": hex(transaction.s),
        "v": transaction.v
    }
    return decoded_transaction


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
