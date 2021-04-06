#!/usr/bin/env python3

from web3 import (
    Web3, HTTPProvider, WebsocketProvider
)
from typing import (
    Optional, Union
)

import requests
import json

from .providers import HTTP_PROVIDER
from .utils import (
    amount_unit_converter, is_address, to_checksum_address
)
from .exceptions import (
    APIError, ProviderError, AddressError, BalanceError
)
from .config import config


def get_balance(address: str, provider: Union[HTTPProvider, WebsocketProvider] = HTTP_PROVIDER) -> int:
    """
    Get XinFin balance.

    :param address: XinFin address.
    :type address: HTTPProvider, WebsocketProvider
    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: str

    :returns: int -- XinFin balance (Wei).

    >>> from pyxdc.rpc import get_balance
    >>> from pyxdc.providers import HTTP_PROVIDER
    >>> get_balance(address="xdc70c1eb09363603a3b6391deb2daa6d2561a62f52", provider=HTTP_PROVIDER)
    71560900
    """

    if not isinstance(provider, (HTTPProvider, WebsocketProvider)):
        raise ProviderError(f"Unknown XinFin provider",
                            "choose only 'HTTP_PROVIDER' or 'WEBSOCKET_PROVIDER' providers.")
    if not is_address(address=address):
        raise AddressError(f"Invalid XinFin '{address}' address.")

    web3: Web3 = Web3(provider=provider)
    return web3.eth.get_balance(
        to_checksum_address(address=address, prefix="0x")
    )


# def estimate_transaction_fee(address: str, amount: int, asset: str = config["asset"],
#                              confirmations: int = config["confirmations"], network: str = config["network"],
#                              vapor: bool = config["vapor"], headers: dict = config["headers"],
#                              timeout: int = config["timeout"]) -> int:
#     """
#     Estimate transaction fee.
#
#     :param address: XinFin address.
#     :type address: str
#     :param amount: XinFin amount.
#     :type amount: int
#     :param asset: XinFin asset id, default to BTM asset.
#     :type asset: str
#     :param confirmations: XinFin confirmations, default to 1.
#     :type confirmations: int
#     :param network: XinFin network, defaults to solonet.
#     :type network: str
#     :param vapor: XinFin sidechain vapor, defaults to False.
#     :type vapor: bool
#     :param headers: Request headers, default to common headers.
#     :type headers: dict
#     :param timeout: request timeout, default to 60.
#     :type timeout: int
#     :returns: str -- Estimated transaction fee.
#
#     >>> from pyxdc.rpc import estimate_transaction_fee
#     >>> from pyxdc.assets import BTM as ASSET
#     >>> estimate_transaction_fee(address="bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", asset=ASSET, amount=100_000, confirmations=6, network="mainnet", vapor=False)
#     "0.0044900000"
#     >>> estimate_transaction_fee(address="vp1q9ndylx02syfwd7npehfxz4lddhzqsve2za23ag", asset=ASSET, amount=100_000_000, confirmations=100, network="mainnet", vapor=True)
#     "0.0089800000"
#     """
#
#     if not is_network(network=network):
#         raise NetworkError(f"Invalid '{network}' network",
#                            "choose only 'mainnet', 'solonet' or 'testnet' networks.")
#     if vapor:
#         if not is_address(address=address, network=network, vapor=True):
#             raise AddressError(f"Invalid Vapor '{address}' {network} address.")
#         url = f"{config['sidechain'][network]['mov']}/merchant/estimate-tx-fee"
#     else:
#         if not is_address(address=address, network=network, vapor=False):
#             raise AddressError(f"Invalid '{address}' {network} address.")
#         url = f"{config['mainchain'][network]['mov']}/merchant/estimate-tx-fee"
#
#     data = dict(
#         asset_amounts={
#             asset: str(amount_converter(
#                 amount=amount, symbol="NEU2BTM"
#             ))
#         },
#         confirmations=confirmations
#     )
#     params = dict(address=address)
#     response = requests.post(
#         url=url, data=json.dumps(data), params=params, headers=headers, timeout=timeout
#     )
#     if response.status_code == 200 and response.json()["code"] == 200:
#         return amount_converter(amount=float(response.json()["data"]["fee"]), symbol="BTM2NEU")
#     raise APIError(response.json()["msg"], response.json()["code"])
#
#
# def build_transaction(address: str, transaction: dict, network: str = config["network"],
#                       vapor: bool = config["vapor"], headers: dict = config["headers"],
#                       timeout: int = config["timeout"]) -> dict:
#     """
#     Build XinFin transaction in blockcenter.
#
#     :param address: XinFin address.
#     :type address: str
#     :param transaction: XinFin transaction.
#     :type transaction: dict
#     :param network: XinFin network, defaults to solonet.
#     :type network: str
#     :param vapor: XinFin sidechain vapor, defaults to False.
#     :type vapor: bool
#     :param headers: Request headers, default to common headers.
#     :type headers: dict
#     :param timeout: request timeout, default to 60.
#     :type timeout: int
#     :returns: dict -- XinFin built transaction.
#
#     >>> from pyxdc.rpc import build_transaction
#     >>> build_transaction(address, transaction, "mainnet")
#     {"transaction": {"hash": "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492", "status_fail": false, "size": 379, "submission_timestamp": 0, "memo": "", "inputs": [{"script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2450000000, "type": "spend"}], "outputs": [{"utransactiono_id": "5edccebe497893c289121f9e365fdeb34c97008b9eb5a9960fe9541e7923aabc", "script": "01642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c0", "address": "smart contract", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 1000, "type": "control"}, {"utransactiono_id": "f8cfbb692db1963be88b09c314adcc9e19d91c6c019aa556fb7cb76ba8ffa1fa", "script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2439999000, "type": "control"}], "fee": 10000000, "balances": [{"asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": "-10001000"}], "types": ["ordinary"]}, "raw_transaction": "070100010160015e7f2d7ecec3f61d30d0b2968973a3ac8448f0599ea20dce883b48c903c4d6e87fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8091a0900901011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a22012091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e20201ad01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe80701880101642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c000013dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff98dcbd8b09011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a00", "signing_instructions": [{"derivation_path": ["2c000000", "99000000", "01000000", "00000000", "01000000"], "sign_data": ["37727d44af9801e9723eb325592f4d55cc8d7e3815b1d663d61b7f1af9fc13a7"], "pubkey": "91ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e2"}], "fee": 10000000}
#     """
#
#     if not is_network(network=network):
#         raise NetworkError(f"Invalid '{network}' network",
#                            "choose only 'mainnet', 'solonet' or 'testnet' networks.")
#     if vapor:
#         if not is_address(address=address, network=network, vapor=True):
#             raise AddressError(f"Invalid '{address}' {network} vapor address.")
#         url = f"{config['sidechain'][network]['blockcenter']}/merchant/build-advanced-tx"
#     else:
#         if not is_address(address=address, network=network, vapor=False):
#             raise AddressError(f"Invalid '{address}' {network} address.")
#         url = f"{config['mainchain'][network]['blockcenter']}/merchant/build-advanced-tx"
#     params = dict(address=address)
#     response = requests.post(
#         url=url, data=json.dumps(transaction), params=params, headers=headers, timeout=timeout
#     )
#     if response.status_code == 200 and response.json()["code"] == 300:
#         raise APIError(response.json()["msg"], response.json()["code"])
#     elif response.status_code == 200 and response.json()["code"] == 503:
#         raise APIError(response.json()["msg"], response.json()["code"])
#     elif response.status_code == 200 and response.json()["code"] == 422:
#         raise BalanceError(f"There is no any asset balance recorded on this '{address}' address.")
#     elif response.status_code == 200 and response.json()["code"] == 515:
#         raise BalanceError(f"Insufficient balance, check your balance and try again.")
#     elif response.status_code == 200 and response.json()["code"] == 504:
#         raise BalanceError(f"Insufficient balance, check your balance and try again.")
#     return response.json()["data"][0]
#
#
# def get_transaction(transaction_id: str, network: str = config["network"], vapor: bool = config["vapor"],
#                     headers: dict = config["headers"], timeout: int = config["timeout"]) -> dict:
#     """
#     Get XinFin transaction detail.
#
#     :param transaction_id: XinFin transaction id.
#     :type transaction_id: str
#     :param network: XinFin network, defaults to solonet.
#     :type network: str
#     :param vapor: XinFin sidechain vapor, defaults to False.
#     :type vapor: bool
#     :param headers: Request headers, default to common headers.
#     :type headers: dict
#     :param timeout: request timeout, default to 60.
#     :type timeout: int
#     :returns: dict -- XinFin transaction detail.
#
#     >>> from pyxdc.rpc import get_transaction
#     >>> get_transaction(transaction_id, "mainnet")
#     {"transaction": {"hash": "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492", "status_fail": false, "size": 379, "submission_timestamp": 0, "memo": "", "inputs": [{"script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2450000000, "type": "spend"}], "outputs": [{"utransactiono_id": "5edccebe497893c289121f9e365fdeb34c97008b9eb5a9960fe9541e7923aabc", "script": "01642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c0", "address": "smart contract", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 1000, "type": "control"}, {"utransactiono_id": "f8cfbb692db1963be88b09c314adcc9e19d91c6c019aa556fb7cb76ba8ffa1fa", "script": "00142cda4f99ea8112e6fa61cdd26157ed6dc408332a", "address": "bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", "asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": 2439999000, "type": "control"}], "fee": 10000000, "balances": [{"asset": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount": "-10001000"}], "types": ["ordinary"]}, "raw_transaction": "070100010160015e7f2d7ecec3f61d30d0b2968973a3ac8448f0599ea20dce883b48c903c4d6e87fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8091a0900901011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a22012091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e20201ad01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe80701880101642091ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e220ac13c0bb1445423a641754182d53f0677cd4351a0e743e6f10b35122c3d7ea01202b9a5949f5546f63a253e41cda6bffdedb527288a7e24ed953f5c2680c70d6ff741f547a6416000000557aa888537a7cae7cac631f000000537acd9f6972ae7cac00c000013dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff98dcbd8b09011600142cda4f99ea8112e6fa61cdd26157ed6dc408332a00", "signing_instructions": [{"derivation_path": ["2c000000", "99000000", "01000000", "00000000", "01000000"], "sign_data": ["37727d44af9801e9723eb325592f4d55cc8d7e3815b1d663d61b7f1af9fc13a7"], "pubkey": "91ff7f525ff40874c4f47f0cab42e46e3bf53adad59adef9558ad1b6448f22e2"}], "fee": 10000000}
#     """
#
#     if not is_network(network=network):
#         raise NetworkError(f"Invalid '{network}' network",
#                            "choose only 'mainnet', 'solonet' or 'testnet' networks.")
#     if vapor:
#         url = f"{config['sidechain'][network]['blockmeta']}/tx/hash/{transaction_id}"
#         response = requests.get(
#             url=url, headers=headers, timeout=timeout
#         )
#         if response.status_code == 200 and response.json()["code"] == 200:
#             return response.json()["data"]["transaction"]
#         raise APIError(f"Not found this '{transaction_id}' vapor transaction id.", 500)
#     else:
#         url = f"{config['mainchain'][network]['blockmeta']}/transaction/{transaction_id}"
#         response = requests.get(
#             url=url, headers=headers, timeout=timeout
#         )
#         if response.status_code == 200 and response.json()["inputs"] is not None:
#             return response.json()
#         raise APIError(f"Not found this '{transaction_id}' transaction id.", 500)
#
#
# def decode_transaction_raw(transaction_raw: str, network: str = config["network"], vapor: bool = config["vapor"],
#                            headers: dict = config["headers"], timeout: int = config["timeout"]) -> dict:
#     """
#     Get decode transaction raw.
#
#     :param transaction_raw: XinFin transaction raw.
#     :type transaction_raw: str
#     :param network: XinFin network, defaults to solonet.
#     :type network: str
#     :param vapor: XinFin sidechain vapor, defaults to False.
#     :type vapor: bool
#     :param headers: Request headers, default to common headers.
#     :type headers: dict
#     :param timeout: request timeout, default to 60.
#     :type timeout: int
#     :returns: dict -- XinFin decoded transaction raw.
#
#     >>> from pyxdc.rpc import decode_transaction_raw
#     >>> decode_transaction_raw(transaction_raw, "testnet")
#     {...}
#     """
#
#     if not is_network(network=network):
#         raise NetworkError(f"Invalid '{network}' network",
#                            "choose only 'mainnet', 'solonet' or 'testnet' networks.")
#     if vapor:
#         url = f"{config['sidechain'][network]['vapor-core']}/decode-raw-transaction"
#     else:
#         url = f"{config['mainchain'][network]['bytom-core']}/decode-raw-transaction"
#     data = dict(raw_transaction=transaction_raw)
#     response = requests.post(
#         url=url, data=json.dumps(data), headers=headers, timeout=timeout
#     )
#     if response.status_code == 400:
#         raise APIError(response.json()["msg"], response.json()["code"])
#     return response.json()["data"]
#
#
# def submit_transaction_raw(address: str, transaction_raw: str, signatures: list,
#                            network: str = config["network"], vapor: bool = config["vapor"],
#                            headers: dict = config["headers"], timeout: int = config["timeout"]) -> str:
#     """
#      Submit transaction raw to XinFin blockchain.
#
#     :param address: XinFin address.
#     :type address: str
#     :param transaction_raw: XinFin transaction raw.
#     :type transaction_raw: str
#     :param signatures: XinFin signed datas.
#     :type signatures: list
#     :param network: XinFin network, defaults to solonet.
#     :type network: str
#     :param vapor: XinFin sidechain vapor, defaults to False.
#     :type vapor: bool
#     :param headers: Request headers, default to common headers.
#     :type headers: dict
#     :param timeout: request timeout, default to 60.
#     :type timeout: int
#     :returns: dict -- XinFin transaction id/hash.
#
#     >>> from pyxdc.rpc import submit_transaction_raw
#     >>> submit_transaction_raw("bm1q9ndylx02syfwd7npehfxz4lddhzqsve2fu6vc7", transaction_raw, [[...], [...]], "mainent")
#     "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492"
#     """
#
#     if not is_network(network=network):
#         raise NetworkError(f"Invalid '{network}' network",
#                            "choose only 'mainnet', 'solonet' or 'testnet' networks.")
#     if vapor:
#         if not is_address(address=address, network=network, vapor=True):
#             raise AddressError(f"Invalid '{address}' {network} vapor address.")
#         url = f"{config['sidechain'][network]['blockcenter']}/merchant/submit-payment"
#     else:
#         if not is_address(address=address, network=network, vapor=False):
#             raise AddressError(f"Invalid '{address}' {network} address.")
#         url = f"{config['mainchain'][network]['blockcenter']}/merchant/submit-payment"
#     data = dict(raw_transaction=transaction_raw, signatures=signatures)
#     params = dict(address=address)
#     response = requests.post(
#         url=url, data=json.dumps(data), params=params, headers=headers, timeout=timeout
#     )
#     if requests.status_codes == 200 and response.json()["code"] != 200:
#         raise APIError(response.json()["msg"], response.json()["code"])
#     return response.json()["data"]["tx_hash"]
