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
def cid(client):
    conlist = client.call(MsfRpcMethod.ConsoleList)
    for c in conlist['consoles']:
        return c['id']

def test_login(client):
    assert isinstance(client, MsfRpcClient)
    tl = client.call(MsfRpcMethod.AuthTokenList)
    assert 'tokens' in tl
    assert len(tl['tokens']) > 1 # There should be temp token and UUID perm token
    for x in tl['tokens']:
        if 'TEMP' in x:
            continue
        assert 'TEMP' not in x

def test_consolecreate(client):
    condict = client.call(MsfRpcMethod.ConsoleCreate)
    assert 'id' in condict

def test_consolelist(client):
    conlist = client.call(MsfRpcMethod.ConsoleList)
    assert 'consoles' in conlist
    assert len(conlist['consoles']) > 0

def test_consolereadwrite(client, cid):
    conwrite = client.call(MsfRpcMethod.ConsoleWrite, [cid, "show options\n"])
    assert conwrite['wrote'] == 13
    time.sleep(1)
    conread = client.call(MsfRpcMethod.ConsoleRead, [cid])
    assert "Global Options" in conread['data']

def test_console_manager_list(client):
    conlist = client.consoles.list
    for x in conlist:
        assert 'id' in x
        break

def test_console_manager_readwrite(client, cid):
    client.consoles.console(cid).write("show options")
    out = client.consoles.console(cid).read()
    assert 'Global Options' in out['data']

def test_moduleinfo(client):
    modinfo = client.call(MsfRpcMethod.ModuleInfo, [None, "exploit/windows/smb/ms08_067_netapi"])
    assert modinfo['name'] == "MS08-067 Microsoft Server Service Relative Path Stack Corruption"

def test_pluginloaded(client):
    plugins = client.call(MsfRpcMethod.PluginLoaded)
    assert 'msgrpc' in plugins['plugins']