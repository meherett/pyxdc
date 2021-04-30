#!/usr/bin/env python3

from web3 import (
    Web3, HTTPProvider, WebsocketProvider
)
from typing import Union

from .utils import (
    amount_unit_converter, is_address, to_checksum_address
)
from .exceptions import (
    ProviderError, AddressError, UnitError
)
from .config import config

# XinFin configuration
config: dict = config


def get_balance(address: str,
                provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"],
                unit: str = "Wei"
                ) -> int:
    """
    Get XinFin balance.

    :param address: XinFin address.
    :type address: str
    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider
    :param unit: XinFIn unit, default to Wei
    :type unit: str

    :returns: int -- XinFin balance (Wei).

    >>> from pyxdc import HTTP_PROVIDER
    >>> from pyxdc.rpc import get_balance
    >>> get_balance(address="xdc70c1eb09363603a3b6391deb2daa6d2561a62f52", provider=HTTP_PROVIDER)
    71560900
    """

    if not isinstance(provider, (HTTPProvider, WebsocketProvider)):
        raise ProviderError(f"Unknown XinFin provider",
                            "choose only 'HTTP_PROVIDER' or 'WEBSOCKET_PROVIDER' providers.")
    if not is_address(address=address):
        raise AddressError(f"Invalid XinFin '{address}' address.")
    if unit not in ["XDC", "Gwei", "Wei"]:
        raise UnitError("Invalid XinFin unit", "choose only 'XDC', 'Gwei' or 'Wei' units.")

    web3: Web3 = Web3(provider=provider)
    balance: int = web3.eth.get_balance(
        to_checksum_address(address=address, prefix="0x")
    )
    return balance if unit == "Wei" else amount_unit_converter(amount=balance, unit=f"Wei2{unit}")


def get_transaction(transaction_hash: str,
                    provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]) -> dict:
    """
    Get XinFin transaction detail.

    :param transaction_hash: XinFin transaction hash.
    :type transaction_hash: str
    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider

    :returns: dict -- XinFin transaction detail.

    >>> from pyxdc.rpc import get_transaction
    >>> get_transaction(transaction_hash="0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060")
    {"transaction": {"hash": "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492", "status_fail": false, "size": 379, "submission_timestamp": 0, "memo": "", "inputs": [{"script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2450000000, "type": "spend"}], "outputs": [{"utransactiono_id": "5edccebe497893c289121f9e365fdeb34c97008b9eb5a9960fe9541e7923aabc", "script": "01642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c0", "address": "smart contract", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 1000, "type": "control"}, {"utransactiono_id": "f8cfbb692db1963be88b09c314adcc9e19d91c6c019aa556fb7cb76ba8ffa1fa", "script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2439999000, "type": "control"}], "fee": 10000000, "balances": [{"asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": "-10001000"}], "types": ["ordinary"]}, "raw_transaction": "070100010160015e7f2d7ecec3f61d30d0b2968973a3ac8448f0599ea20dce883b48c903c4d6e87fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8091a0900901011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a22012091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e20201ad01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe80701880101642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c000013dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff98dcbd8b09011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a00", "signing_instructions": [{"derivation_path": ["2c000000", "99000000", "01000000", "00000000", "01000000"], "sign_data": ["37727d44af9801e9723eb325592f4d55cc8d7e3815b1d663d61b7f1af9fc13a7"], "pubkey": "91ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e2"}], "fee": 10000000}
    """

    if not isinstance(provider, (HTTPProvider, WebsocketProvider)):
        raise ProviderError(f"Unknown XinFin provider",
                            "choose only 'HTTP_PROVIDER' or 'WEBSOCKET_PROVIDER' providers.")

    web3: Web3 = Web3(provider=provider)
    transaction_dict: dict = web3.eth.get_transaction(transaction_hash)
    return transaction_dict.__dict__


def submit_transaction_raw(transaction_raw: str,
                           provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]) -> str:
    """
    Submit XinFin transaction raw.

    :param transaction_raw: XinFin transaction raw.
    :type transaction_raw: str
    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider

    :returns: str -- XinFin submitted transaction hash.

    >>> from pyxdc import HTTP_PROVIDER
    >>> from pyxdc.rpc import submit_transaction_raw
    >>> submit_transaction_raw(transaction_raw="xdc70c1eb09363603a3b6391deb2daa6d2561a62f52", provider=HTTP_PROVIDER)
    "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492"
    """

    if not isinstance(provider, (HTTPProvider, WebsocketProvider)):
        raise ProviderError(f"Unknown XinFin provider",
                            "choose only 'HTTP_PROVIDER' or 'WEBSOCKET_PROVIDER' providers.")

    web3: Web3 = Web3(provider=provider)
    transaction_hash: bytes = web3.eth.send_raw_transaction(transaction_raw)
    return transaction_hash.hex()
