#!/usr/bin/env python3

from types import SimpleNamespace
from typing import (
    Union, Optional
)
from web3 import (
    Web3, HTTPProvider, WebsocketProvider
)
from web3.contract import ContractConstructor

from .wallet import Wallet
from .exceptions import UnitError
from .utils import (
    to_checksum_address, decode_transaction_raw, amount_unit_converter, is_root_xprivate_key
)
from .config import config

# XinFin configuration
config: dict = config


class NestedNamespace(SimpleNamespace):
    def __init__(self, dictionary, **kwargs):
        super().__init__(**kwargs)
        for key, value in dictionary.items():
            if isinstance(value, dict):
                self.__setattr__(key, NestedNamespace(value))
            else:
                self.__setattr__(key, value)


class TransactionParameters(NestedNamespace):

    HASH:       Optional[str] = None
    FROM:       Optional[str] = None
    TO:         Optional[str] = None
    NONCE:      Optional[int] = None
    GAS:        Optional[int] = None
    GAS_PRICE:  Optional[int] = None
    CHAIN_ID:   Optional[int] = None
    VALUE:      Optional[int] = None
    DATA:       Optional[str] = None
    RAW:        Optional[str] = None
    R:          Optional[str] = None
    S:          Optional[str] = None
    V:          Optional[int] = None


class Transaction:
    """
    XinFin Transaction.

    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider

    :returns: Transaction -- XinFin transaction instance.
    """

    def __init__(self, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]):

        self.transaction: Optional[TransactionParameters] = None
        self.provider: Union[HTTPProvider,  WebsocketProvider] = provider
        self.web3: Web3 = Web3(provider=self.provider)

    def fee(self, unit: str = "Wei") -> Union[int, float]:
        """
        Get XinFin transaction fee/gas.

        :param unit: XinFIn unit, default to ``Wei``.
        :type unit: str

        :returns: int, float -- XinFin transaction fee/gas.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.transaction import NormalTransaction
        >>> transaction: NormalTransaction = NormalTransaction(provider=HTTP_PROVIDER)
        >>> transaction.build_transaction(...)
        >>> transaction.fee()
        367400
        """

        if unit not in ["XDC", "Gwei", "Wei"]:
            raise UnitError("Invalid XinFin unit", "choose only 'XDC', 'Gwei' or 'Wei' units.")

        return self.transaction.GAS if unit == "Wei" else amount_unit_converter(
            amount=self.transaction.GAS, unit=f"Wei2{unit}"
        )

    def hash(self) -> str:
        """
        Get XinFin transaction hash.

        :returns: str -- XinFin transaction hash.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.transaction import NormalTransaction
        >>> transaction: NormalTransaction = NormalTransaction(provider=HTTP_PROVIDER)
        >>> transaction.build_transaction(...)
        >>> transaction.hash()
        "2993414225f65390220730d0c1a356c14e91bca76db112d37366df93e364a492"
        """

        if not self.transaction.RAW:
            raise ValueError("Build and sign transaction first.")
        return self.transaction.HASH

    def json(self) -> dict:
        """
        Get XinFin transaction json format.

        :returns: dict -- XinFin transaction json format.

        >>> from pyxdc import WEBSOCKET_PROVIDER
        >>> from pyxdc.transaction import ContractTransaction
        >>> transaction: ContractTransaction = ContractTransaction(provider=WEBSOCKET_PROVIDER)
        >>> transaction.build_transaction(...)
        >>> transaction.json()
        {'gas': 134320, 'gasPrice': 20000000000, 'chainId': 1337, 'from': '0x053929E43A1eF27E3822E7fb193527edE04C415B', 'nonce': 15, 'value': 100, 'to': '0x9f77B9f27e8Bc8ad0b58FBf99aeA28feEC7eC50b', 'data': '0x335ef5bd00000000000000000000000031aa61a5d8756c84ebdf0f34e01cab90514f2a573a26da82ead15a80533a02696656b14b5dbfd84eb14790f2e1be5e9e45820eeb000000000000000000000000000000000000000000000000000000005ea55961'}
        """

        if not self.transaction.RAW:
            raise ValueError("Build and sign transaction first.")
        return decode_transaction_raw(transaction_raw=self.transaction.RAW)

    def raw(self) -> str:
        """
        Get XinFin transaction raw.

        :returns: str -- XinFin transaction raw.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.transaction import ContractTransaction
        >>> transaction: ContractTransaction = ContractTransaction(provider=HTTP_PROVIDER)
        >>> transaction.build_transaction(...)
        >>> transaction.raw()
        "f8cc0f8504a817c80083020cb0949f77b9f27e8bc8ad0b58fbf99aea28feec7ec50b64b864335ef5bd00000000000000000000000031aa61a5d8756c84ebdf0f34e01cab90514f2a573a26da82ead15a80533a02696656b14b5dbfd84eb14790f2e1be5e9e45820eeb000000000000000000000000000000000000000000000000000000005ea55961820a95a08bae7e0a7481d11518f7771fedc6f25ab5cc85bc24a0767573ce60e52a090c8da04d6efaafedc5096ecc998cdbca5b3ea4fc6b009b44a8041b8c71be5520c3a356"
        """

        if not self.transaction.RAW:
            raise ValueError("Build and sign transaction first.")
        return self.transaction.RAW


class ContractTransaction(Transaction):
    """
    XinFin Contract Transaction.

    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider

    :returns: ContractTransaction -- XinFin contract transaction instance.
    """

    def __init__(self, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]):
        super().__init__(provider=provider)

        self.transaction = TransactionParameters

    def build_transaction(self, address: str, abi: list, bytecode: str, value: int = 0,
                          gas: Optional[int] = None, estimate_gas: bool = True,
                          gas_price: int = config["gas_price"], *args, **kwargs) -> "ContractTransaction":
        """
        Build XinFin contract transaction.

        :param address: XinFin from address.
        :type address: str
        :param abi: XinFin smart contact abi.
        :type abi: list
        :param bytecode: XinFin smart contact bytecode.
        :type bytecode: str
        :param value: XinFin Wei value, defaults to ``0``.
        :type value: int
        :param gas: XinFin transaction fee/gas, defaults to ``None``.
        :type gas: int
        :param estimate_gas: XinFin transaction estimate fee/gas, defaults to ``True``.
        :type estimate_gas: bool
        :param gas_price: XinFin gas price, defaults to ``0.25 Gwei``.
        :type gas_price: int

        :returns: ContractTransaction -- XinFin contract transaction instance.

        >>> from pyxdc import WEBSOCKET_PROVIDER
        >>> from pyxdc.transaction import ContractTransaction
        >>> contract_transaction: ContractTransaction = ContractTransaction(provider=WEBSOCKET_PROVIDER)
        >>> contract_transaction.build_transaction(address="xdc571ae1504e92fa40f85359efdb188c704a224eac", abi=[...], bytecode="...", value=0, estimate_gas=True)
        <pyxdc.transaction.ContractTransaction object at 0x0409DAF0>
        """

        self.transaction.FROM = to_checksum_address(address=address, prefix="0x")
        self.web3.eth.default_account = self.transaction.FROM

        constructed_contact: ContractConstructor = self.web3.eth.contract(
            abi=abi, bytecode=bytecode
        ).constructor(*args)

        self.transaction.VALUE = value
        if gas is not None:
            self.transaction.GAS = gas
        elif not gas and estimate_gas:
            self.transaction.GAS = constructed_contact.estimateGas(**kwargs)
        else:
            raise ValueError("Gas is required, or set true estimate gas.")
        self.transaction.DATA = constructed_contact.__dict__.get("data_in_transaction")
        self.transaction.NONCE = self.web3.eth.get_transaction_count(self.transaction.FROM)
        self.transaction.GAS_PRICE = gas_price  # self.web3.eth.gasPrice
        return self

    def sign_transaction(self, private_key: Optional[str] = None,
                         root_xprivate_key: Optional[str] = None, path: str = config["path"]) -> "ContractTransaction":
        """
        Sign XinFin contract transaction.

        :param private_key: XinFin private key, default to ``None``.
        :type private_key: str
        :param root_xprivate_key: XinFin root xprivate key, default to ``None``.
        :type root_xprivate_key: str
        :param path: XinFin derivation path, default to ``DEFAULT_PATH``.
        :type path: str

        :returns: ContractTransaction -- Signed XinFin contract transaction instance.

        >>> from pyxdc import WEBSOCKET_PROVIDER
        >>> from pyxdc.transaction import ContractTransaction
        >>> contract_transaction: ContractTransaction = ContractTransaction(provider=WEBSOCKET_PROVIDER)
        >>> contract_transaction.build_transaction(address="xdc571ae1504e92fa40f85359efdb188c704a224eac", abi=[...], bytecode="...", value=0, estimate_gas=True)
        >>> contract_transaction.sign_transaction(private_key="4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de")
        <pyxdc.transaction.ContractTransaction object at 0x0409DAF0>
        """

        if root_xprivate_key is not None:
            if not is_root_xprivate_key(xprivate_key=root_xprivate_key):
                raise ValueError("Invalid XinFin root xprivate key.")
            wallet = Wallet(provider=self.provider)
            wallet.from_root_xprivate_key(root_xprivate_key=root_xprivate_key)
            wallet.from_path(path=path)
            private_key = wallet.private_key()
        elif private_key is not None:
            if len(private_key) != 64:
                raise ValueError("Invalid XinFin private key.")
        else:
            raise ValueError("XinFin root xprivate key or private key is required.")

        signed_transaction = self.web3.eth.account.sign_transaction(
            transaction_dict={
                "from": self.transaction.FROM,
                "nonce": self.transaction.NONCE,
                "gas": self.transaction.GAS,
                "gasPrice": self.transaction.GAS_PRICE,
                "value": self.transaction.VALUE,
                "data": self.transaction.DATA
            }, private_key=private_key
        )

        self.transaction.HASH = signed_transaction.hash.hex()
        self.transaction.RAW = signed_transaction.rawTransaction.hex()
        self.transaction.R = hex(signed_transaction.r)
        self.transaction.S = hex(signed_transaction.s)
        self.transaction.V = signed_transaction.v
        self.transaction.CHAIN_ID = (
            (self.transaction.V - 35) // 2 if self.transaction.V % 2 else (self.transaction.V - 36) // 2
        )
        return self

    @staticmethod
    def clean_modifiers(modifiers):
        cleaned_modifiers = modifiers.copy()
        for name, modifier in modifiers.items():
            for key, value in modifier.items():
                if not isinstance(value, str) or not isinstance(value, int):
                    cleaned_modifiers[name][key] = str(value)
        return cleaned_modifiers


class NormalTransaction(Transaction):
    """
    XinFin Normal Transaction.

    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider

    :returns: NormalTransaction -- XinFin normal transaction instance.
    """

    def __init__(self, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"]):
        super().__init__(provider=provider)

        self.transaction = TransactionParameters

    def build_transaction(self, address: str, recipient: str, value: int,
                          gas: Optional[int] = None, estimate_gas: bool = True,
                          gas_price: int = config["gas_price"]) -> "NormalTransaction":
        """
        Build XinFin normal transaction.
        
        :param address: XinFin from address.
        :type address: str
        :param recipient: Recipients XinFin address.
        :type recipient: str
        :param value: XinFin Wei value.
        :type value: int
        :param gas: XinFin transaction fee/gas, defaults to ``None``.
        :type gas: int
        :param estimate_gas: XinFin transaction estimate fee/gas, defaults to ``True``.
        :type estimate_gas: bool
        :param gas_price: XinFin gas price, defaults to ``0.25 Gwei``.
        :type gas_price: int

        :returns: NormalTransaction -- XinFin normal transaction instance.
        
        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.transaction import NormalTransaction
        >>> normal_transaction: NormalTransaction = NormalTransaction(provider=HTTP_PROVIDER)
        >>> normal_transaction.build_transaction(address="xdc571ae1504e92fa40f85359efdb188c704a224eac", recipient="xdc3e0a9B2Ee8F8341A1aEaD3E7531d75f1e395F24b", value=1_000_000_000, estimate_gas=True)
        <pyxdc.transaction.NormalTransaction object at 0x0409DAF0>
        """

        self.transaction.FROM = to_checksum_address(address=address, prefix="0x")
        self.transaction.TO = to_checksum_address(address=recipient, prefix="0x")
        self.web3.eth.default_account = self.transaction.FROM

        self.transaction.VALUE = value
        if gas is not None:
            self.transaction.GAS = gas
        elif not gas and estimate_gas:
            self.transaction.GAS = self.web3.eth.estimateGas({
                    "from": self.transaction.FROM,
                    "to": self.transaction.TO,
                    "value": self.transaction.VALUE
            })
        else:
            raise ValueError("Gas is required, or set true estimate gas.")
        self.transaction.NONCE = self.web3.eth.get_transaction_count(self.transaction.FROM)
        self.transaction.GAS_PRICE = gas_price  # self.web3.eth.gasPrice
        return self

    def sign_transaction(self, private_key: Optional[str] = None,
                         root_xprivate_key: Optional[str] = None, path: str = config["path"]) -> "NormalTransaction":
        """
        Sign XinFin normal transaction.

        :param private_key: XinFin private key, default to ``None``.
        :type private_key: str
        :param root_xprivate_key: XinFin root xprivate key, default to ``None``.
        :type root_xprivate_key: str
        :param path: XinFin derivation path, default to ``DEFAULT_PATH``.
        :type path: str

        :returns: NormalTransaction -- Signed XinFin normal transaction instance.

        >>> from pyxdc import HTTP_PROVIDER, DEFAULT_PATH
        >>> from pyxdc.transaction import NormalTransaction
        >>> normal_transaction: NormalTransaction = NormalTransaction(provider=HTTP_PROVIDER)
        >>> normal_transaction.build_transaction(address="xdc571ae1504e92fa40f85359efdb188c704a224eac", recipient="xdc3e0a9B2Ee8F8341A1aEaD3E7531d75f1e395F24b", value=1_000_000_000, estimate_gas=True)
        >>> normal_transaction.sign_transaction(root_xprivate_key="xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz", path=DEFAULT_PATH)
        <pyxdc.transaction.NormalTransaction object at 0x0409DAF0>
        """

        if root_xprivate_key is not None:
            if not is_root_xprivate_key(xprivate_key=root_xprivate_key):
                raise ValueError("Invalid XinFin root xprivate key.")
            wallet = Wallet(provider=self.provider)
            wallet.from_root_xprivate_key(root_xprivate_key=root_xprivate_key)
            wallet.from_path(path=path)
            private_key = wallet.private_key()
        elif private_key is not None:
            if len(private_key) != 64:
                raise ValueError("Invalid XinFin private key.")
        else:
            raise ValueError("XinFin root xprivate key or private key is required.")

        signed_transaction = self.web3.eth.account.sign_transaction(
            transaction_dict={
                "from": self.transaction.FROM,
                "to": self.transaction.TO,
                "nonce": self.transaction.NONCE,
                "gas": self.transaction.GAS,
                "gasPrice": self.transaction.GAS_PRICE,
                "value": self.transaction.VALUE,
            }, private_key=private_key
        )

        self.transaction.HASH = signed_transaction.hash.hex()
        self.transaction.RAW = signed_transaction.rawTransaction.hex()
        self.transaction.R = hex(signed_transaction.r)
        self.transaction.S = hex(signed_transaction.s)
        self.transaction.V = signed_transaction.v
        self.transaction.CHAIN_ID = (
            (self.transaction.V - 35) // 2 if self.transaction.V % 2 else (self.transaction.V - 36) // 2
        )
        return self
