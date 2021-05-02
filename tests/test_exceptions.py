#!/usr/bin/env python3

from pyxdc.exceptions import (
    ProviderError, BalanceError, APIError, AddressError, InvalidURLError,
    ClientError, NotFoundError, UnitError
)

import pytest


def test_exceptions():

    with pytest.raises(ProviderError, match="error"):
        raise ProviderError("error")
    with pytest.raises(ProviderError, match="error, error"):
        raise ProviderError("error", "error")
    with pytest.raises(BalanceError, match="error"):
        raise BalanceError("error")
    with pytest.raises(BalanceError, match="error, error"):
        raise BalanceError("error", "error")
    with pytest.raises(APIError, match="error"):
        raise APIError("error")
    with pytest.raises(APIError):
        raise APIError("error", "error")
    with pytest.raises(AddressError, match="error"):
        raise AddressError("error")
    with pytest.raises(AddressError, match="error, error"):
        raise AddressError("error", "error")
    with pytest.raises(InvalidURLError, match="error"):
        raise InvalidURLError("error")
    with pytest.raises(ClientError, match="error"):
        raise ClientError("error")
    with pytest.raises(ClientError):
        raise ClientError("error", "error")
    with pytest.raises(NotFoundError, match="error"):
        raise NotFoundError("error")
    with pytest.raises(UnitError, match="error"):
        raise UnitError("error")
    with pytest.raises(UnitError, match="error, error"):
        raise UnitError("error", "error")
