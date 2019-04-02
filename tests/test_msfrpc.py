#!/usr/bin/env python3

import pytest

from src.metasploit.msfrpc import *

def test_login():
    client = MsfRpcClient('123')
    assert client != None

def test_