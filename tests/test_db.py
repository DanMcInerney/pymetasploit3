#!/usr/bin/env python3

import pytest
import os
from pymetasploit3.msfrpc import *


@pytest.fixture()
def client():
    client = MsfRpcClient('123', port=55552)
    yield client
    client.call(MsfRpcMethod.AuthLogout)


def test_hosts(client):
    default_workspace_hosts = client.db.workspaces.workspace('default').hosts.list
    assert 'created_at' in default_workspace_hosts[0] # requires that db is connected and you've had a session


def test_list(client):
    workspace_list = client.db.workspaces.list
    assert workspace_list[0]['name'] == 'default'


def test_note_add(client):
    type_of_note = 'pytest'
    data_of_note = 'pytest data string'
    client.db.workspaces.workspace('default').notes.report(type_of_note, data_of_note, update='unique')
    note = client.db.workspaces.workspace('default').notes.find(ntype='pytest')
    assert note[0]['data'] == '"pytest data string"'


# Metasploit issue: https://github.com/rapid7/metasploit-framework/issues/11755
#def test_workspace_note_del(client):
#    client.call('db.del_note', [{'workspace':'default', 'ntype':'pytest'}])
# or
#    client.db.workspaces.workspace('default').notes.delete(ntype='pytest')


# There is no RPC API call for deleting loot
def test_loot(client):
    client.db.workspaces.workspace('default').loots.report(path='pytest', rtype='pytest', data='pytest', host='1.1.1.1')
    loot_list = client.db.workspaces.workspace('default').loots.list
    assert loot_list[0]['data'] == 'pytest'


def test_hosts_add(client):
    client.db.workspaces.workspace('default').hosts.report(host='1.1.1.2')
    hosts = client.db.workspaces.workspace('default').hosts.list
    host_found = False
    for d in hosts:
        if d['address'] == '1.1.1.2':
            host_found = True
            break
    assert host_found == True


def test_hosts_del(client):
    client.db.workspaces.workspace('default').hosts.delete(host='1.1.1.2')
    hosts = client.db.workspaces.workspace('default').hosts.list
    host_found = False
    for d in hosts:
        if d['address'] == '1.1.1.2':
            host_found = True
            break
    assert host_found == False


def test_services_add(client):
    client.db.workspaces.workspace().services.report(host='1.1.1.3', port=1, proto='tcp')
    services = client.db.workspaces.workspace().services.list
    service_found = False
    for d in services:
        if d['host'] == '1.1.1.3' and d['port'] == 1 and d['proto'] == 'tcp':
            service_found = True
            break
    assert service_found == True


def test_services_del(client):
    client.db.workspaces.workspace().services.delete(host='1.1.1.3')
    services = client.db.workspaces.workspace().services.list
    service_found = False
    for d in services:
        if d['host'] == '1.1.1.3' and d['port'] == 1 and d['proto'] == 'tcp':
            service_found = True
            break
    assert service_found == False


def test_vuln_add(client):
    host = '1.1.1.4'
    name = 'pytest'
    client.db.workspaces.workspace('default').vulns.report(host, name)
    vuln = client.db.workspaces.workspace('default').vulns.get(host='1.1.1.4')
    assert vuln[0]['host'] == '1.1.1.4'


# Metasploit issue: https://github.com/rapid7/metasploit-framework/issues/11756
#def test_vuln_del(client):
#    client.call('db.del_vuln', [{'workspace':'default', 'host':'1.1.1.4'}])
# or
#    client.db.workspaces.workspace('default').vulns.delete(host='1.1.1.4')


def test_workspaces_add(client):
    client.db.workspaces.add('pytest')
    ws = client.db.workspaces.get('pytest')
    assert ws[0]['name'] == 'pytest'


def test_workspaces_importfile(client):
    client.db.workspaces.set('pytest')
    cur = client.db.workspaces.current.current
    assert cur == 'pytest'
    test_file = os.getcwd() + '/test.xml'
    client.db.workspaces.workspace(cur).importfile(test_file)
    assert client.db.workspaces.workspace(cur).hosts.get(host='192.168.1.2')[0]['address'] == '192.168.1.2'
    client.db.workspaces.set('default')


def test_workspaces_del(client):
    client.db.workspaces.remove('pytest')
    ws = client.db.workspaces.list
    found = False
    for d in ws:
        if d['name'] == 'pytest':
            found = True
    assert found == False
