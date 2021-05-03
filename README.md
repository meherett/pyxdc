# PyXDC

[![Build Status](https://travis-ci.org/meherett/pyxdc.svg?branch=master)](https://travis-ci.org/meherett/pyxdc?branch=master)
[![PyPI Version](https://img.shields.io/pypi/v/pyxdc.svg?color=blue)](https://pypi.org/project/pyxdc)
[![Documentation Status](https://readthedocs.org/projects/pyxdc/badge/?version=master)](https://pyxdc.readthedocs.io/en/master/?badge=master)
[![PyPI Python Version](https://img.shields.io/pypi/pyversions/pyxdc.svg)](https://pypi.org/project/pyxdc)
[![Coverage Status](https://coveralls.io/repos/github/meherett/pyxdc/badge.svg?branch=master)](https://coveralls.io/github/meherett/pyxdc?branch=master)

Python library with tools for XinFin blockchain. 

## Installation

```
$ pip install pyxdc
```

If you want to run the latest version of the code, you can install from git:

```
$ pip install git+git://github.com/meherett/pyxdc.git
```

For the versions available, see the [tags on this repository](https://github.com/meherett/pyxdc/tags).

## Development

We welcome pull requests. To get started, just fork this repository, clone it locally, and run:

```
$ pip install -e .[tests] -r requirements.txt
```

## Testing

You can run the tests with:

```
$ pytest
```

Or use `tox` to run the complete suite against the full set of build targets, or pytest to run specific 
tests against a specific version of Python.

## License

Distributed under the [MIT](https://github.com/meherett/pyxdc/blob/master/LICENSE) license. See ``LICENSE`` for more information.
