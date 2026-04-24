#!/usr/bin/env python

try:
    from setuptools import setup, find_packages
except ImportError:
    raise ImportError("setuptools is required to install wifite2")

from wifite.config import Configuration

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='wifite',
    version=Configuration.version,
    author='kimocoder',
    author_email='christian@aircrack-ng.org',
    url='https://github.com/kimocoder/wifite2',
    packages=find_packages(exclude=['tests', 'tests.*']),
    package_data={
        '': ['wordlists/*.txt']
    },
    license='GNU GPLv2',
    scripts=['bin/wifite'],
    description='Wireless Network Auditor for Linux & Android',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ]
)
