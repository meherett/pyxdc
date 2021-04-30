#!/usr/bin/env python3

from web3 import (
    Web3, HTTPProvider, WebsocketProvider
)
from typing import Union

from .rpc import get_balance
from .utils import to_checksum_address
from .config import config

# XinFin configuration
config: dict = config


class Account(str):

    def __new__(cls, address: str, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]):
        obj = super().__new__(cls, address)
        obj.provider = provider
        obj.web3 = Web3(provider=provider)
        obj.address = to_checksum_address(address=address, prefix="0x")
        return obj

    def transfer(self, address: str, value: int):
        self.web3.eth.sendTransaction(transaction={
            "to": to_checksum_address(address=address, prefix="0x"), "from": self.address, "value": value
        })

    @property
    def balance(self, unit: str = "Wei"):
        return get_balance(address=self.address, provider=self.provider, unit=unit)
