#!/usr/bin/env python3

import pytest
from src.metasploit.msfrpc import *


@pytest.fixture()
def client():
    client = MsfRpcClient('123')
    yield client
    client.call(MsfRpcMethod.AuthLogout)

@pytest.fixture()
def sid(client):
    sid = [id for id in client.sessions.list.keys()][0]
    assert int(sid)
    yield sid

def test_sessions_list(client):
    sess_list = client.sessions.list
    assert type(sess_list) == dict

def test_sessions_module_list(client, sid):
    assert 'post/' in client.sessions.session(sid).modules[0]

def test_sessions_read(client, sid):
    assert type(client.sessions.session(sid).read()) == str



