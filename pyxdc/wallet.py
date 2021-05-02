#!/usr/bin/env python3

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.keys import (
    SigningKey, VerifyingKey
)
from ecdsa.ecdsa import (
    int_to_string, string_to_int
)
from web3 import (
    HTTPProvider, WebsocketProvider
)
from binascii import (
    hexlify, unhexlify
)
from mnemonic import Mnemonic
from hashlib import sha256
from typing import (
    Optional, Any, Union
)

import hmac
import ecdsa
import struct
import sha3
import unicodedata
import hashlib

from .libs.base58 import (
    check_encode, checksum_encode, check_decode, ensure_string
)
from .signature import (
    sign, verify
)
from .rpc import get_balance
from .utils import (
    get_bytes, is_entropy, is_mnemonic, get_entropy_strength, __unhexlify__,
    get_mnemonic_language, is_root_xprivate_key, get_mnemonic_strength
)
from .config import config


CURVE_GEN: Any = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER: int = CURVE_GEN.order()
FIELD_ORDER: int = SECP256k1.curve.p()
INFINITY: Point = ecdsa.ellipticcurve.INFINITY

# XinFin configuration
config: dict = config


class Wallet:
    """
    XinFin Wallet.

    :param provider: XinFin provider, default to ``HTTP_PROVIDER``.
    :type provider: HTTPProvider, WebsocketProvider
    :param use_default_path: Use default derivation path, defaults to ``False``.
    :type use_default_path: bool

    :returns: Wallet -- Wallet instance.
    """

    def __init__(self, provider: Union[HTTPProvider, WebsocketProvider] = config["providers"]["http"],
                 use_default_path: bool = False):

        self._provider: Union[HTTPProvider, WebsocketProvider] = provider
        self._use_default_path: bool = use_default_path

        self._strength: Optional[int] = None
        self._entropy: Optional[str] = None
        self._mnemonic: Optional[str] = None
        self._language: Optional[str] = None
        self._passphrase: Optional[str] = None

        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self._i: Optional[bytes] = None
        self._path: str = "m"

        self._seed: Optional[bytes] = None
        self._private_key: Optional[bytes] = None
        self._key: Optional[SigningKey] = None
        self._verified_key: Optional[VerifyingKey] = None

        self._private_key: Optional[bytes] = None
        self._public_key: Optional[str] = None
        self._chain_code: Optional[bytes] = None
        self._depth: int = 0
        self._index: int = 0

    def from_entropy(self, entropy: str, language: str = "english", passphrase: Optional[str] = None) -> "Wallet":
        """
        Master from Entropy hex string.

        :param entropy: Entropy hex string.
        :type entropy: str
        :param language: Mnemonic language, default to ``english``.
        :type language: str
        :param passphrase: Mnemonic passphrase or password, default to ``None``.
        :type passphrase: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import WEBSOCKET_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=WEBSOCKET_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e", language="english", passphrase=None)
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        if not is_entropy(entropy=entropy):
            raise ValueError("Invalid entropy.")
        if language and language not in ["english", "french", "italian", "japanese",
                                         "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
            raise ValueError("Invalid language, choose only the following options 'english', 'french', 'italian', "
                             "'spanish', 'chinese_simplified', 'chinese_traditional', 'japanese or 'korean' languages.")

        self._strength = get_entropy_strength(entropy=entropy)
        self._entropy, self._language = unhexlify(entropy), language
        self._passphrase = str(passphrase) if passphrase else str()
        mnemonic = Mnemonic(language=self._language).to_mnemonic(data=self._entropy)
        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_mnemonic(self, mnemonic: str, language: str = None, passphrase: str = None) -> "Wallet":
        """
        Master from Mnemonic words.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param language: Mnemonic language, default to ``None``.
        :type language: str
        :param passphrase: Mnemonic passphrase or password, default to ``None``.
        :type passphrase: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_mnemonic(mnemonic="rent host ill marble fortune deputy pink absorb stand thought neck planet away found robust", passphrase=None)
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        if not is_mnemonic(mnemonic=mnemonic, language=language):
            raise ValueError("Invalid mnemonic words.")

        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._strength = get_mnemonic_strength(mnemonic=self._mnemonic)
        self._language = language if language else get_mnemonic_language(mnemonic=self._mnemonic)
        self._entropy = Mnemonic(language=self._language).to_entropy(self._mnemonic)
        self._passphrase = str(passphrase) if passphrase else str()
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_seed(self, seed: str) -> "Wallet":
        """
        Master from Seed hex string.

        :param seed: Seed hex string.
        :type seed: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_seed(seed="09d6f96646d69b3842eecb8f05737972c6c0314d60c203657ae2dad5e8dd88797019ad9938292307de2f4a74018d8797324abab779432eb428aea1855694156b")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        self._seed = unhexlify(seed)
        self._i = hmac.new(b"Bitcoin seed", get_bytes(seed), hashlib.sha512).digest()
        il, ir = self._i[:32], self._i[32:]
        parse_il = int.from_bytes(il, "big")
        if parse_il == 0 or parse_il >= SECP256k1.order:
            raise ValueError("Bad seed, resulting in invalid key!")

        self._private_key, self._chain_code = il, ir
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=config["path"])
        self._public_key = self.compressed()
        return self

    def from_root_xprivate_key(self, root_xprivate_key: str) -> "Wallet":
        """
        Master from Root XPrivate Key.

        :param root_xprivate_key: Root xprivate key.
        :type root_xprivate_key: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_root_xprivate_key(root_xprivate_key="xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        if not is_root_xprivate_key(xprivate_key=root_xprivate_key):
            raise ValueError("Invalid Root XPrivate Key.")

        _deserialize_xprivate_key = self._deserialize_xprivate_key(xprivate_key=root_xprivate_key)
        self._depth, self._parent_fingerprint, self._index = (0, b"\0\0\0\0", 0)
        self._i = _deserialize_xprivate_key[5] + _deserialize_xprivate_key[4]
        self._private_key, self._chain_code = self._i[:32], self._i[32:]
        self._key = ecdsa.SigningKey.from_string(_deserialize_xprivate_key[5], curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=config["path"])
        self._public_key = self.compressed()
        return self

    def from_xprivate_key(self, xprivate_key: str) -> "Wallet":
        """
        Master from XPrivate Key.

        :param xprivate_key: XPrivate key.
        :type xprivate_key: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_xprivate_key(xprivate_key="xprvA2oDuneWodkNiecDi8VoBCvu7TSfnDmGqr5oKzkkLWvmE9dm1TQzYcp9HZQLqYTep1T3yykxZgiUSJDZYrvnnL1txNUd3o2y1A1t5xz3d8H")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        _deserialize_xprivate_key = self._deserialize_xprivate_key(xprivate_key=xprivate_key)
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_deserialize_xprivate_key[1], "big"),
            _deserialize_xprivate_key[2],
            struct.unpack(">L", _deserialize_xprivate_key[3])[0]
        )
        self._private_key, self._chain_code = _deserialize_xprivate_key[5], _deserialize_xprivate_key[4]
        self._key = ecdsa.SigningKey.from_string(_deserialize_xprivate_key[5], curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_wif(self, wif: str) -> "Wallet":
        """
        Master from Wallet Important Format (WIF).

        :param wif: Wallet important format.
        :type wif: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_wif(wif="KySR2sF6eTQyYRr3SW12jm5KPycKmgQ9SGUJ7oBQPf1SnvuvJTat")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        raw = check_decode(wif)[:-1]
        if not raw.startswith(__unhexlify__(config["wif"])):
            raise ValueError(f"Invalid XinFin wallet important format.")

        self._private_key = raw.split(__unhexlify__(config["wif"]), 1).pop()
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_private_key(self, private_key: str) -> "Wallet":
        """
        Master from Private Key.

        :param private_key: Private key.
        :type private_key: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_private_key(private_key="4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        self._private_key = unhexlify(private_key)
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_path(self, path: str) -> "Wallet":
        """
        Derivation from Path.

        :param path: Derivation path.
        :type path: str

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_root_xprivate_key(root_xprivate_key="xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz")
        >>> wallet.from_path(path="m/44'/550'/'0/0/0")
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        if path[0:2] != "m/":
            raise ValueError("Bad path, please insert like this type of path \"m/0'/0\"! ")

        for index in path.lstrip("m/").split("/"):
            if "'" in index:
                self._derive_key_by_index(int(index[:-1]) + config["hardened"])
                self._path += str("/" + index)
            else:
                self._derive_key_by_index(int(index))
                self._path += str("/" + index)
        return self

    def from_index(self, index: int, hardened: bool = False) -> "Wallet":
        """
        Derivation from Index.

        :param index: Derivation index.
        :type index: int
        :param hardened: Hardened address, default to ``False``.
        :type hardened: bool

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_root_xprivate_key(root_xprivate_key="xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz")
        >>> wallet.from_index(index=44, hardened=True)
        >>> wallet.from_index(index=550, hardened=True)
        >>> wallet.from_index(index=0, hardened=True)
        >>> wallet.from_index(index=0)
        >>> wallet.from_index(index=0)
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        """

        if not isinstance(index, int):
            raise ValueError("Bad index, Please import only integer number!")

        if hardened:
            self._path += ("/%d'" % index)
            self._derive_key_by_index(index + config["hardened"])
        else:
            self._path += ("/%d" % index)
            return self._derive_key_by_index(index)

    def _derive_key_by_index(self, index) -> Optional["Wallet"]:

        i_str = struct.pack(">L", index)
        if index & config["hardened"]:
            data = b"\0" + self._key.to_string() + i_str
        else:
            data = unhexlify(self.public_key()) + i_str

        if not self._chain_code:
            raise PermissionError("You can't drive xprivate_key and private_key.")

        i = hmac.new(self._chain_code, data, hashlib.sha512).digest()
        il, ir = i[:32], i[32:]

        il_int = string_to_int(il)
        if il_int > CURVE_ORDER:
            return None
        pvt_int = string_to_int(self._key.to_string())
        k_int = (il_int + pvt_int) % CURVE_ORDER
        if k_int == 0:
            return None
        secret = (b"\0" * 32 + int_to_string(k_int))[-32:]

        self._private_key, self._chain_code, self._depth, self._index, self._parent_fingerprint = (
            secret, ir, (self._depth + 1), index, unhexlify(self.finger_print())
        )
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        return self

    @staticmethod
    def _deserialize_xprivate_key(xprivate_key: str, encoded: bool = True) -> tuple:
        decoded_xprivate_key = check_decode(xprivate_key) if encoded else xprivate_key
        if len(decoded_xprivate_key) != 78:  # 156
            raise ValueError("Invalid XPrivate Key.")
        return (
            decoded_xprivate_key[:4], decoded_xprivate_key[4:5],
            decoded_xprivate_key[5:9], decoded_xprivate_key[9:13],
            decoded_xprivate_key[13:45], decoded_xprivate_key[46:]
        )

    @staticmethod
    def _deserialize_xpublic_key(xpublic_key: str, encoded: bool = True) -> tuple:
        decoded_xpublic_key = check_decode(xpublic_key) if encoded else xpublic_key
        if len(decoded_xpublic_key) != 78:  # 156
            raise ValueError("Invalid XPublic Key.")
        return (
            decoded_xpublic_key[:4], decoded_xpublic_key[4:5],
            decoded_xpublic_key[5:9], decoded_xpublic_key[9:13],
            decoded_xpublic_key[13:45], decoded_xpublic_key[45:]
        )

    @staticmethod
    def _serialize_xkeys(version: bytes, depth: bytes, parent_fingerprint: bytes, index: bytes,
                         chain_code: bytes, data: bytes, encoded: bool = True) -> Optional[str]:
        try:
            raw = (version + depth + parent_fingerprint + index + chain_code + data)
            return check_encode(raw) if encoded else raw.hex()
        except TypeError:
            return None

    def root_xprivate_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get Root XPrivate Key.

        :param encoded: Encoded root xprivate key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPrivate Key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/'0/0/0")
        >>> wallet.root_xprivate_key()
        "xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz"
        """

        version = config["extended_private_key"]
        if version is None:
            raise NotImplementedError(self)
        if not self._i:
            return None
        secret_key, chain_code = self._i[:32], self._i[32:]
        depth = bytes(bytearray([0]))
        parent_fingerprint = b"\0\0\0\0"
        index = struct.pack(">L", 0)
        data = b"\x00" + secret_key
        return self._serialize_xkeys(
            __unhexlify__(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def root_xpublic_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get Root XPublic Key.

        :param encoded: Encoded root xpublic key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPublic Key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/'0/0/0")
        >>> wallet.root_xpublic_key()
        "xpub661MyMwAqRbcGCEJcvCiXitgL4Ypa53B2kCofr36SJeQRfVv7hAFQfFio7Qn9R25GrPZZKvvjERGLPBTDWxhyBnkfKpHoQarBxgpqXgtq6X"
        """

        version = config["extended_public_key"]
        if version is None:
            raise NotImplementedError(self)
        if not self._i:
            return None
        secret_key, chain_code = self._i[:32], self._i[32:]
        depth = bytes(bytearray([0]))
        parent_fingerprint = b"\0\0\0\0"
        index = struct.pack(">L", 0)
        data = unhexlify(self.public_key(private_key=secret_key.hex()))
        return self._serialize_xkeys(
            __unhexlify__(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xprivate_key(self, encoded=True) -> Optional[str]:
        """
        Get XPrivate Key.

        :param encoded: Encoded xprivate key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPrivate Key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.xprivate_key()
        "xprvA2oDuneWodkNiecDi8VoBCvu7TSfnDmGqr5oKzkkLWvmE9dm1TQzYcp9HZQLqYTep1T3yykxZgiUSJDZYrvnnL1txNUd3o2y1A1t5xz3d8H"
        """

        version = config["extended_private_key"]
        if version is None:
            raise NotImplementedError(self)
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        data = b"\x00" + unhexlify(self.private_key())
        return self._serialize_xkeys(
            __unhexlify__(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xpublic_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get XPublic Key.

        :param encoded: Encoded xpublic key, default to ``True``.
        :type encoded: bool

        :returns: str -- XPublic Key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.xpublic_key()
        "xpub6FnaKJBQe1Jfw8ggpA2oYLsdfVHABgV8D51Q8PAMtrTk6wxuYzjF6R8d8sX2mAkeqHnGLSuqcGDtsLFtmk8pSSkPeTbRsRBA3LpMSS1c3LE"
        """

        version = config["extended_public_key"]
        if version is None:
            raise NotImplementedError(self)
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        data = unhexlify(self.public_key())
        return self._serialize_xkeys(
            __unhexlify__(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def clean_derivation(self) -> "Wallet":
        """
        Clean derivation Path or Indexes.

        :returns: Wallet -- Wallet instance.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_root_xprivate_key(root_xprivate_key="xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz")
        >>> wallet.from_path(path="m/44'/550'/'0/0/0")
        >>> wallet.path()
        "m/44'/550'/'0/0/0"
        >>> wallet.clean_derivation()
        <pyxdc.wallet.Wallet object at 0x000001E8BFB98D60>
        >>> wallet.path()
        None
        """

        if self._i:
            self._path, self._depth, self._parent_fingerprint, self._index = (
                "m", 0, b"\0\0\0\0", 0
            )
            self._private_key, self._chain_code = self._i[:32], self._i[32:]
            self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()
        return self

    def uncompressed(self) -> str:
        """
        Get Uncommpresed Public Key.

        :returns: str -- Uncommpresed public key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.uncompressed()
        "d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc850af47d43f0d7e156dca7e9ab885a507fc8ccd36e69090f037243daf299db401d"
        """

        return hexlify(self._verified_key.to_string()).decode()

    def compressed(self) -> str:
        """
        Get Commpresed Public Key.

        :returns: str -- Commpresed public key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.compressed()
        "03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85"
        """

        padx = (b"\0" * 32 + int_to_string(
            self._verified_key.pubkey.point.x()))[-32:]
        if self._verified_key.pubkey.point.y() & 1:
            ck = b"\3" + padx
        else:
            ck = b"\2" + padx
        return hexlify(ck).decode()

    def private_key(self) -> str:
        """
        Get Private Key.

        :returns: str -- Private key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.private_key()
        "4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de"
        """

        return hexlify(self._key.to_string()).decode()

    def public_key(self, private_key: str = None) -> str:
        """
        Get Public Key.

        :returns: str -- Public key.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.public_key()
        "03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85"
        """

        if private_key:
            key = ecdsa.SigningKey.from_string(
                unhexlify(private_key), curve=SECP256k1)
            verified_key = key.get_verifying_key()
            padx = (b"\0" * 32 + int_to_string(
                verified_key.pubkey.point.x()))[-32:]
            if verified_key.pubkey.point.y() & 1:
                ck = b"\3" + padx
            else:
                ck = b"\2" + padx
            return hexlify(ck).decode()
        return self.compressed()

    def strength(self) -> Optional[int]:
        """
        Get Entropy strength.

        :returns: int -- Entropy strength.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.strength()
        160
        """

        return self._strength if self._strength else None

    def entropy(self) -> Optional[str]:
        """
        Get Entropy hex string.

        :returns: str -- Entropy hex string.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.entropy()
        "b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e"
        """

        return hexlify(self._entropy).decode() if self._entropy else None

    def mnemonic(self) -> Optional[str]:
        """
        Get Mnemonic words.

        :returns: str -- Mnemonic words.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.mnemonic()
        "venture fitness paper little blush april rigid where find volcano fetch crack label polar dash"
        """

        return unicodedata.normalize("NFKD", self._mnemonic) if self._mnemonic else None

    def passphrase(self) -> Optional[str]:
        """
        Get Entopy/Mnemonic passphrase.

        :returns: str -- Entopy/Mnemonic passphrase.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e", passphrase="meherett")
        >>> wallet.passphrase()
        "meherett"
        """

        return str(self._passphrase) if self._passphrase else None

    def language(self) -> Optional[str]:
        """
        Get Mnemonic language.

        :returns: str -- Mnemonic language.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.language()
        "english"
        """

        return str(self._language) if self._language else None

    def seed(self) -> Optional[str]:
        """
        Get Seed hex string.

        :returns: str -- Seed hex string.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.seed()
        "09d6f96646d69b3842eecb8f05737972c6c0314d60c203657ae2dad5e8dd88797019ad9938292307de2f4a74018d8797324abab779432eb428aea1855694156b"
        """

        return hexlify(self._seed).decode() if self._seed else None

    def path(self) -> Optional[str]:
        """
        Get Derivation path.

        :returns: str -- Drivation path.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.path()
        "m/44'/550'/0'/0/0"
        """

        return str(self._path) if not self._path == "m" else None

    def chain_code(self) -> Optional[str]:
        """
        Get Chain code.

        :returns: str -- Chain code.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.chain_code()
        "fb40b46da06b4940be76a38e1962aa34f362c47ccb16707b5e21e71514a98d93"
        """

        return hexlify(self._chain_code).decode() if self._chain_code else None

    @staticmethod  # It's constant value
    def semantic() -> Optional[str]:
        """
        Get Extended semantic.

        :returns: str -- Extended semantic.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.semantic()
        "p2pkh"
        """

        return "p2pkh"  # Pay to Public Key Hash type.

    def hash(self, private_key: str = None):
        """
        Get Public Key Hash.

        :returns: str -- Identifier/Hash.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.hash()
        "197a8b4ad8fbbe118487e065cc8595bf67845aeb"
        """

        return hashlib.new("ripemd160", sha256(unhexlify(self.public_key(
            private_key=private_key if private_key else self.private_key()
        ))).digest()).hexdigest()

    def finger_print(self) -> str:
        """
        Get Finger print.

        :returns: str -- Finger print.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.finger_print()
        "197a8b4a"
        """

        return self.hash(self.private_key())[:8]

    def address(self, prefix: str = "xdc") -> str:
        """
        Get Address.

        :returns: str -- XinFin Address.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.address()
        "xdc9Cd6fD3519b259B251d881361CAae6BABdC5910b"
        """

        keccak_256 = sha3.keccak_256()
        keccak_256.update(self._verified_key.to_string())
        address = keccak_256.hexdigest()[24:]
        return checksum_encode(address, prefix=prefix)

    def wif(self) -> str:
        """
        Get Wallet Important Format.

        :returns: str -- Wallet Important Format.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.wif()
        "KySR2sF6eTQyYRr3SW12jm5KPycKmgQ9SGUJ7oBQPf1SnvuvJTat"
        """

        raw = __unhexlify__(config["wif"]) + self._key.to_string() + b"\x01"
        return check_encode(raw)

    def balance(self, unit: str = "Wei") -> Union[int, float]:
        """
        Get XinFin wallet balance.

        :param unit: XinFIn unit, default to ``Wei``.
        :type unit: str

        :return: int, float -- XinFin balance (XDC, Gwei, Wei).

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.balance()
        2450000000
        """

        return get_balance(address=self.address(), provider=self._provider, unit=unit)

    def sign(self, message: Optional[str] = None, message_hash: Optional[str] = None) -> str:
        """
        Sign message data by private key.

        :param message: Message data, default to None.
        :type message: str.
        :param message_hash: Message data hash, default to None.
        :type message_hash: str.

        :return: str -- Signed message data (signature).

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> message = "1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.sign(message=message)
        "9c3a1322cab0e70147c85e47bdc3ce7d719130b70857bb7ac633e9bd7a76f3b8d76eddd83f1a5d229a34491b7e26aaae21a091920b12ce81c618cbb1f5accf4a"
        """

        return sign(private_key=self.private_key(), message=message, message_hash=message_hash)

    def verify(self, signature: str, message: Optional[str] = None, message_hash: Optional[str] = None) -> bool:
        """
        Verify signature by public key.

        :param signature: Signed message data.
        :type signature: str.
        :param message: Message data, default to None.
        :type message: str.
        :param message_hash: Message data hash, default to None.
        :type message_hash: str.

        :return: bool -- Verified signature (True/False).

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> message = "1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"
        >>> signature = "9c3a1322cab0e70147c85e47bdc3ce7d719130b70857bb7ac633e9bd7a76f3b8d76eddd83f1a5d229a34491b7e26aaae21a091920b12ce81c618cbb1f5accf4a"
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.verify(message=message, signature=signature)
        True
        """

        return verify(public_key=self.public_key(), signature=signature, message=message, message_hash=message_hash)

    def dumps(self) -> dict:
        """
        Get All Wallet imformations.

        :returns: dict -- All Wallet imformations.

        >>> from pyxdc import HTTP_PROVIDER
        >>> from pyxdc.wallet import Wallet
        >>> wallet: Wallet = Wallet(provider=HTTP_PROVIDER)
        >>> wallet.from_entropy(entropy="b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e")
        >>> wallet.from_path(path="m/44'/550'/0'/0/0")
        >>> wallet.dumps()
        {'strength': 160, 'entropy': 'b64dc1c3c3d5b876a94006d49c1e4ed2f106b86e', 'mnemonic': 'rent host ill marble fortune deputy pink absorb stand thought neck planet away found robust', 'language': 'english', 'passphrase': None, 'seed': '09d6f96646d69b3842eecb8f05737972c6c0314d60c203657ae2dad5e8dd88797019ad9938292307de2f4a74018d8797324abab779432eb428aea1855694156b', 'root_xprivate_key': 'xprv9s21ZrQH143K3i9qWtfiAawwn2iLAcKKfXHCsTdUsy7RYsAma9qzrrwEwsu9buLocH7qFQmTow5bSysKDmq8VB3hYPQgMTmXAfdmhNdRZYz', 'root_xpublic_key': 'xpub661MyMwAqRbcGCEJcvCiXitgL4Ypa53B2kCofr36SJeQRfVv7hAFQfFio7Qn9R25GrPZZKvvjERGLPBTDWxhyBnkfKpHoQarBxgpqXgtq6X', 'xprivate_key': 'xprvA2oDuneWodkNiecDi8VoBCvu7TSfnDmGqr5oKzkkLWvmE9dm1TQzYcp9HZQLqYTep1T3yykxZgiUSJDZYrvnnL1txNUd3o2y1A1t5xz3d8H', 'xpublic_key': 'xpub6FnaKJBQe1Jfw8ggpA2oYLsdfVHABgV8D51Q8PAMtrTk6wxuYzjF6R8d8sX2mAkeqHnGLSuqcGDtsLFtmk8pSSkPeTbRsRBA3LpMSS1c3LE', 'uncompressed': 'd8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc850af47d43f0d7e156dca7e9ab885a507fc8ccd36e69090f037243daf299db401d', 'compressed': '03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85', 'chain_code': 'fb40b46da06b4940be76a38e1962aa34f362c47ccb16707b5e21e71514a98d93', 'private_key': '4235d9ffc246d488d527177b654e7dd5c02f5c5abc2e2054038d6825224a24de', 'public_key': '03d8799336beacc6b2e7f86f46bce4ad5cabf1ec7a0d6241416985e3b29fe1cc85', 'wif': 'KySR2sF6eTQyYRr3SW12jm5KPycKmgQ9SGUJ7oBQPf1SnvuvJTat', 'finger_print': '197a8b4a', 'semantic': 'p2pkh', 'path': "m/44'/550'/0'/0/0", 'hash': '197a8b4ad8fbbe118487e065cc8595bf67845aeb', 'address': 'xdc9Cd6fD3519b259B251d881361CAae6BABdC5910b'}
        """

        return dict(
            strength=self.strength(),
            entropy=self.entropy(),
            mnemonic=self.mnemonic(),
            language=self.language(),
            passphrase=self.passphrase(),
            seed=self.seed(),
            root_xprivate_key=self.root_xprivate_key(),
            # root_xprivate_key_hex=self.root_xprivate_key(encoded=False),
            root_xpublic_key=self.root_xpublic_key(),
            # root_xpublic_key_hex=self.root_xpublic_key(encoded=False),
            xprivate_key=self.xprivate_key(),
            # xprivate_key_hex=self.xprivate_key(encoded=False),
            xpublic_key=self.xpublic_key(),
            # xpublic_key_hex=self.xpublic_key(encoded=False),
            uncompressed=self.uncompressed(),
            compressed=self.compressed(),
            chain_code=self.chain_code(),
            private_key=self.private_key(),
            public_key=self.public_key(),
            wif=self.wif(),
            finger_print=self.finger_print(),
            semantic=self.semantic(),
            path=self.path(),
            hash=self.hash(),
            address=self.address()
        )
