#!/usr/bin/env python3

from pyxdc import HTTP_PROVIDER
from pyxdc.rpc import get_balance
from pyxdc.utils import (
    is_address, amount_unit_converter
)

# XinFin mainnet address
ADDRESS_XDC: str = "xdc571ae1504e92fa40f85359efdb188c704a224eac"
# Ethereum mainnet address
ADDRESS_0X: str = "0x571ae1504e92fa40f85359efdb188c704a224eac"

# Check all addresses
assert is_address(address=ADDRESS_XDC)
assert is_address(address=ADDRESS_0X)

# Get all address balances
print("XDC Address Balance:", amount_unit_converter(amount=get_balance(
    address=ADDRESS_XDC, provider=HTTP_PROVIDER
), unit="Wei2XDC"), "XDC")

print("0x Address Balance:", amount_unit_converter(amount=get_balance(
    address=ADDRESS_0X, provider=HTTP_PROVIDER
), unit="Wei2XDC"), "XDC")
