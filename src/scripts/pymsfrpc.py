#!/usr/bin/env python3

from code import InteractiveConsole
from atexit import register
from os import path
import readline

from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
from pymetasploit3.utils import parseargs


class MsfRpc(InteractiveConsole):
    def __init__(self, password, **kwargs):
        self.client = MsfRpcClient(password, **kwargs)
        InteractiveConsole.__init__(self, {'rpc' : self.client}, '<console>')
        self.init_history(path.expanduser('~/.msfrpc_history'))

    def init_history(self, histfile):
        readline.parse_and_bind('tab: complete')
        if hasattr(readline, "read_history_file"):
            try:
                readline.read_history_file(histfile)
            except IOError:
                pass
            register(self.save_history, histfile)

    def save_history(self, histfile):
        readline.write_history_file(histfile)


if __name__ == '__main__':
    o = parseargs()
    try:
        m = MsfRpc(o.__dict__.pop('password'), **o.__dict__)
        m.interact('')
    except MsfRpcError as m:
        print(str(m))
        exit(-1)
    exit(0)
