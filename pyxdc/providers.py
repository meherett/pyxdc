#!/usr/bin/env python3

from web3 import (
    HTTPProvider, WebsocketProvider
)

from .config import config


HTTP_PROVIDER: HTTPProvider = HTTPProvider(
    endpoint_uri=config["providers"]["http"]
)

WEBSOCKET_PROVIDER: WebsocketProvider = WebsocketProvider(
    endpoint_uri=config["providers"]["websocket"]
)
