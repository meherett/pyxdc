# !/usr/bin/env python3

from pyxdc.utils import amount_unit_converter

print(amount_unit_converter(amount=0.25, unit="Gwei2Wei"), "Wei")
print(amount_unit_converter(amount=25_000_000_000, unit="Gwei2XDC"), "XDC")

print(amount_unit_converter(amount=25, unit="XDC2Wei"), "Wei")
print(amount_unit_converter(amount=25, unit="XDC2Gwei"), "Gwei")

print(amount_unit_converter(amount=25_000_000_000_000_000_000, unit="Wei2Gwei"), "Gwei")
print(amount_unit_converter(amount=25_000_000_000_000_000_000, unit="Wei2XDC"), "XDC")

