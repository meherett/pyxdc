#!/usr/bin/env python3

from setuptools import (
    setup, find_packages
)

# README.md
with open("README.md", "r", encoding="utf-8") as readme:
    long_description: str = readme.read()

# requirements.txt
with open("requirements.txt", "r") as _requirements:
    requirements: list = list(map(str.strip, _requirements.read().split("\n")))

setup(
    name="pyxdc",
    version="0.1.0",
    description="Python library with tools for XinFin blockchain.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Meheret Tesfaye",
    author_email="meherett@zoho.com",
    url="https://github.com/meherett/pyxdc",
    keywords=["xinfin", "wallet", "protocol", "blockchain"],
    python_requires=">=3.6,<4",
    packages=find_packages(),
    install_requires=requirements,
    extras_require={
        "tests": [
            "pytest>=6.2.3,<7",
            "pytest-cov>=2.11.1,<3"
        ],
        "docs": [
            "sphinx>=3.5.4,<4",
            "sphinx-rtd-theme>=0.5.2,<1"
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
)
