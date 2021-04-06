#!/usr/bin/env python3

from typing import List

from .wallet import Wallet
from .config import config

# XinFin configuration
config: dict = config

# XinFin providers
HTTP_PROVIDER, WEBSOCKET_PROVIDER = (
    config["providers"]["http"], config["providers"]["websocket"]
)


__all__: List[str] = [
    "Wallet", "HTTP_PROVIDER", "WEBSOCKET_PROVIDER"
]
