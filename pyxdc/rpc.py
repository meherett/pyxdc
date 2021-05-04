#!/usr/bin/env python3

from web3 import (
    Web3, HTTPProvider, WebsocketProvider
)
from typing import Union

import requests

from .utils import (
    amount_unit_converter, is_address, to_checksum_address
)
from .exceptions import (
    ProviderError, AddressError, UnitError, APIError
)
from .config import config

# XinFin configuration
config: dict = config


def get_balance(address: str, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"], unit: str = "Wei") -> Union[int, float]:
    """
    Get XinFin balance.

    :param address: XinFin address.
    :type address: str
    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider
    :param unit: XinFIn unit, default to ``Wei``.
    :type unit: str

    :returns: int, float -- XinFin balance (XDC, Gwei, Wei).

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


def get_transaction(transaction_hash: str, headers: dict = config["headers"], timeout: int = config["timeout"]) -> dict:
    """
    Get XinFin transaction detail.

    :param transaction_hash: XinFin transaction hash.
    :type transaction_hash: str
    :param headers: Request headers, default to common headers.
    :type headers: dict
    :param timeout: Request timeout, default to 15.
    :type timeout: int

    :returns: dict -- XinFin transaction detail.

    >>> from pyxdc.rpc import get_transaction
    >>> get_transaction(transaction_hash="0xa4d57071427e3310b3e2fb16e7712f8d8aaaafb31ce5fcd6534fc50848905948")
    {'hash': '0xa4d57071427e3310b3e2fb16e7712f8d8aaaafb31ce5fcd6534fc50848905948', 'nonce': 0, 'blockHash': '0xb33a804ae10713bf549db8ec749f7d650347613ac784db1a8d17e0cb03741bf0', 'blockNumber': 1, 'transactionIndex': 0, 'from': '0x96cA14396341480E3b6384D1d1397d1f7f5a0AB7', 'to': None, 'value': 0, 'gas': 367400, 'gasPrice': 250000000, 'input': '0x608060405234801561001057600080fd5b506040518060400160405280600581526020017f48656c6c6f0000000000000000000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50610166565b82805461006e90610105565b90600052602060002090601f01602090048101928261009057600085556100d7565b82601f106100a957805160ff19168380011785556100d7565b828001600101855582156100d7579182015b828111156100d65782518255916020019190600101906100bb565b5b5090506100e491906100e8565b5090565b5b808211156101015760008160009055506001016100e9565b5090565b6000600282049050600182168061011d57607f821691505b6020821081141561013157610130610137565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b61053b806101756000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063a413686214610046578063cfae321714610062578063ef690cc014610080575b600080fd5b610060600480360381019061005b91906102e3565b61009e565b005b61006a6100b8565b604051610077919061035d565b60405180910390f35b61008861014a565b604051610095919061035d565b60405180910390f35b80600090805190602001906100b49291906101d8565b5050565b6060600080546100c790610433565b80601f01602080910402602001604051908101604052809291908181526020018280546100f390610433565b80156101405780601f1061011557610100808354040283529160200191610140565b820191906000526020600020905b81548152906001019060200180831161012357829003601f168201915b5050505050905090565b6000805461015790610433565b80601f016020809104026020016040519081016040528092919081815260200182805461018390610433565b80156101d05780601f106101a5576101008083540402835291602001916101d0565b820191906000526020600020905b8154815290600101906020018083116101b357829003601f168201915b505050505081565b8280546101e490610433565b90600052602060002090601f016020900481019282610206576000855561024d565b82601f1061021f57805160ff191683800117855561024d565b8280016001018555821561024d579182015b8281111561024c578251825591602001919060010190610231565b5b50905061025a919061025e565b5090565b5b8082111561027757600081600090555060010161025f565b5090565b600061028e610289846103a4565b61037f565b9050828152602081018484840111156102a657600080fd5b6102b18482856103f1565b509392505050565b600082601f8301126102ca57600080fd5b81356102da84826020860161027b565b91505092915050565b6000602082840312156102f557600080fd5b600082013567ffffffffffffffff81111561030f57600080fd5b61031b848285016102b9565b91505092915050565b600061032f826103d5565b61033981856103e0565b9350610349818560208601610400565b610352816104f4565b840191505092915050565b600060208201905081810360008301526103778184610324565b905092915050565b600061038961039a565b90506103958282610465565b919050565b6000604051905090565b600067ffffffffffffffff8211156103bf576103be6104c5565b5b6103c8826104f4565b9050602081019050919050565b600081519050919050565b600082825260208201905092915050565b82818337600083830152505050565b60005b8381101561041e578082015181840152602081019050610403565b8381111561042d576000848401525b50505050565b6000600282049050600182168061044b57607f821691505b6020821081141561045f5761045e610496565b5b50919050565b61046e826104f4565b810181811067ffffffffffffffff8211171561048d5761048c6104c5565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f830116905091905056fea264697066735822122002786b5114bea14354170503b8bffe80a17bb5e4610cb41deca549935965f30864736f6c63430008030033', 'v': 28, 'r': '0xa593dcfd7f7b17f8b22907e9c4b03721312a4d00dfd99f8f7267ccd5eb7d4613', 's': '0x70cd172ae92de7a046dfe28de1db8657f8c3b3ed00c060392fb1d5080646927b'}
    """

    url = f"{config['endpoint']}/publicAPI"
    params = dict(
        module="transaction",
        action="gettxdetails",
        txhash=transaction_hash,
        apikey=None
    )
    response = requests.get(
        url=url, params=params, headers=headers, timeout=timeout
    )
    if response.status_code == 200 and response.json()["status"] == 1:
        return response.json()["result"]
    elif response.status_code == 200 and response.json()["status"] == 0:
        raise APIError(
            status_code=response.status_code,
            error_message=response.json()["message"]
        )
    else:
        raise APIError(
            status_code=response.status_code,
            error_message=response.content
        )


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
    >>> submit_transaction_raw(transaction_raw="0xf86c02840ee6b280825208943e0a9b2ee8f8341a1aead3e7531d75f1e395f24b8901236efcbcbb340000801ba03084982e4a9dd897d3cc1b2c8cc2d1b106b9d302eb23f6fae7d0e57e53e043f8a0116f13f9ab385f6b53e7821b3335ced924a1ceb88303347cd0af4aa75e6bfb73", provider=HTTP_PROVIDER)
    "0x04b3bfb804f2b3329555c6f3a17a794b3f099b6435a9cf58c78609ed93853907"
    """

    if not isinstance(provider, (HTTPProvider, WebsocketProvider)):
        raise ProviderError(f"Unknown XinFin provider",
                            "choose only 'HTTP_PROVIDER' or 'WEBSOCKET_PROVIDER' providers.")

    web3: Web3 = Web3(provider=provider)
    transaction_hash: bytes = web3.eth.send_raw_transaction(transaction_raw)
    return transaction_hash.hex()
