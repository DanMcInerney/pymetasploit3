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
    c_id = client.call(MsfRpcMethod.ConsoleCreate)['id']
    yield c_id
    destroy = client.call(MsfRpcMethod.ConsoleDestroy, [c_id])
    assert destroy['result'] == 'success'


def test_consolelist(client):
    conlist = client.call(MsfRpcMethod.ConsoleList)
    assert 'consoles' in conlist
    assert type(conlist['consoles']) == list


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


def test_console_create(client):
    cid = client.consoles.console().cid
    client.consoles.destroy(cid)
    assert int(cid)


def test_console_manager_readwrite(client, cid):
    client.consoles.console(cid).write("show options")
    out = client.consoles.console(cid).read()
    assert 'Global Options' in out['data']


def test_console_is_busy(client, cid):
    assert client.consoles.console(cid).is_busy() == False

def test_console_execute_with_cmd(client, cid):
    x = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
    x['RHOSTS'] = '127.0.0.1'
    out = client.consoles.console(cid).execute_module_with_output(x, payload='cmd/unix/interact')
    assert type(out) == str
    assert '[*] Exploit completed, but no session was created.'.lower() in out.lower()