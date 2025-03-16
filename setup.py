#!/usr/bin/env python
import os

from setuptools import setup

PACKAGE_NAME = "timeroast_ng"


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name=PACKAGE_NAME,
    version="0.1-dev0",
    description=(
        "Implementation of the Timeroasting attack to grab hashes from computer accounts "
        "using SNTP-MS."
    ),
    url="https://github.com/MatrixEditor/timeroast-ng",
    author="MatrixEditor",
    license="MIT",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    platforms=["Unix", "Windows"],
    scripts=[
        os.path.join(".", "timeroast-ng.py"),
        os.path.join(".", "resolveRID.py"),
    ],
    install_requires=["impacket", "rich"],
    classifiers=[
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
    ],
)
