#!/usr/bin/env python3

import pytest
import time
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

def test_sessions_runsingle(client, sid):
    assert type(client.sessions.session(sid).runsingle('')) == str

def test_sessions_readwrite(client, sid):
    s = client.sessions.session(sid)
    s.write('help')
    out = ''
    while len(out) == 0:
        time.sleep(1)
        out = s.read()
    assert '\nCore Commands\n=============\n\n' in out

def test_sessions_run_with_output(client, sid):
    s = client.sessions.session(sid)
    cmd = 'arp'
    end_strs = ['----']
    out = s.run_with_output(cmd, end_strs)
    assert 'ARP cache' in out


