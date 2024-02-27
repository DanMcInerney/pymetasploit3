#!/usr/bin/env python3

from code import InteractiveConsole
from atexit import register
from sys import stdout
from os import path
import readline

from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.utils import parseargs


class MsfConsole(InteractiveConsole):

    def __init__(self, password, **kwargs):
        self.fl = True
        self.client = MsfRpcConsole(MsfRpcClient(password, **kwargs), cb=self.callback)
        InteractiveConsole.__init__(self, {'rpc': self.client})
        self.init_history(path.expanduser('~/.msfconsole_history'))

    def raw_input(self, prompt):
        line = InteractiveConsole.raw_input(self, prompt=self.client.prompt)
        return "rpc.execute('%s')" % line.replace("'", r"\'")

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
        del self.client
        print('bye!')

    def callback(self, d):
        stdout.write('\n%s' % d['data'])
        if not self.fl:
            stdout.write('\n%s' % d['prompt'])
            stdout.flush()
        else:
            self.fl = False


if __name__ == '__main__':
    o = parseargs()
    try:
        m = MsfConsole(o.__dict__.pop('password'), **o.__dict__)
        m.interact('')
    except MsfRpcError as m:
        print(str(m))
        exit(-1)
    exit(0)
