#!/usr/bin/env python3

import pytest

from src.metasploit.msfrpc import *


@pytest.fixture()
def client():
    client = MsfRpcClient('123')
    yield client
    client.call(MsfRpcMethod.AuthLogout)


@pytest.fixture()
def cid(client):
    c_id = client.call(MsfRpcMethod.ConsoleCreate)['id']
    yield c_id
    destroy = client.call(MsfRpcMethod.ConsoleDestroy, [c_id])
    assert destroy['result'] == 'success'

def test_jobs(client):
    assert type(client.jobs.list) == dict

def test_login(client):
    assert isinstance(client, MsfRpcClient)
    tl = client.call(MsfRpcMethod.AuthTokenList)
    assert 'tokens' in tl
    assert len(tl['tokens']) > 1 # There should be temp token and UUID perm token
    nontemp_token = False
    for x in tl['tokens']:
        if 'TEMP' in x:
            continue
        if 'TEMP' not in x:
            nontemp_token = True
            break
    assert nontemp_token == True


def test_pluginloaded(client):
    plugins = client.call(MsfRpcMethod.PluginLoaded)
    assert 'msgrpc' in plugins['plugins']