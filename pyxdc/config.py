#!/usr/bin/env python3

from web3 import (
    HTTPProvider, WebsocketProvider
)

# XinFin - XDC configuration
config: dict = {
    "hardened": 0x80000000,
    "extended_private_key": 0x0488ade4,
    "extended_public_key": 0x0488b21e,
    "providers": {
      "http": HTTPProvider(
          endpoint_uri="https://rpc.xinfin.network"
      ),
      "websocket": WebsocketProvider(
          endpoint_uri="wss://ws.xinfin.network"
      )
    },
    "timeout": 60,
    "units": {
        "XDC": 1,
        "Gwei": 1_000_000_000,
        "Wei": 1_000_000_000_000_000_000
    },
    "coin_type": 550,
    "path": "m/44/550/1/0/1",
    "fee": 10_000_000,
    "wif": 0x80,
    "headers": {
        "User-Agent": "PyXDC User-Agent v0.1.0",
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json"
    }
}
