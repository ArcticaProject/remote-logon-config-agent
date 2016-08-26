#!/usr/bin/python3

from setuptools import setup
import re

setup(
    name='thinclient-config-agent',
    version=re.search(r'\((.*)\)', open('debian/changelog').readline()).group(1),
    license='GPL',
    description='Retrieve the list of remote desktop servers for a user.',
    long_description='Retrieve the list of remote desktop servers for a user.',
    packages=['tccalib'],
    test_suite='tccalib',
)
