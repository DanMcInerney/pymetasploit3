#!/usr/bin/env python3

import pytest
import time
import os
from pymetasploit3.msfrpc import *


@pytest.fixture()
def client():
    client = MsfRpcClient('123', port=55552)
    yield client
    client.call(MsfRpcMethod.AuthLogout)

@pytest.fixture()
def meterpreter_sid(client):
    s = client.sessions.list
    for sid in s:
        if s[sid]['type'] == 'meterpreter':
            assert int(sid)
            yield sid

@pytest.fixture()
def shell_sid(client):
    s = client.sessions.list
    for sid in s:
        if s[sid]['type'] == 'shell':
            assert int(sid)
            yield sid

def test_list(client):
    sess_list = client.sessions.list
    assert type(sess_list) == dict


def test_met_module_list(client, meterpreter_sid):
    assert 'post/' in client.sessions.session(meterpreter_sid).modules[0]


def test_read(client, meterpreter_sid):
    assert type(client.sessions.session(meterpreter_sid).read()) == str


def test_runsingle(client, meterpreter_sid):
    assert type(client.sessions.session(meterpreter_sid).runsingle('')) == str


def test_met_readwrite(client, meterpreter_sid):
    s = client.sessions.session(meterpreter_sid)
    s.write('help')
    out = ''
    while len(out) == 0:
        time.sleep(1)
        out = s.read()
    assert '\nCore Commands\n=============\n\n' in out


def test_met_run_with_output(client, meterpreter_sid):
    s = client.sessions.session(meterpreter_sid)
    cmd = 'arp'
    end_strs = ['----']
    out = s.run_with_output(cmd, end_strs)
    assert 'ARP cache' in out


def test_shell_run_with_output(client, shell_sid):
    s = client.sessions.session(shell_sid)
    cmd = 'whoami'
    end_strs = ['>']
    out = s.run_with_output(cmd, end_strs)
    assert '\\' in out


def test_psh_script(client, meterpreter_sid):
    s = client.sessions.session(meterpreter_sid)
    path = os.getcwd()
    path += '/Invoke-Mimikatz.ps1'
    out = s.import_psh(path)
    assert 'success' in out
    out = s.run_psh_cmd('Invoke-Mimikatz')
    assert 'mimikatz' in out
