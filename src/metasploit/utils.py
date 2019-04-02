#!/usr/bin/env python3

from optparse import OptionParser
import msgpack

__all__ = [
    'parseargs',
    'convert',
    'decode',
    'encode'
]


def parseargs():
    p = OptionParser()
    p.add_option("-P", dest="password", help="Specify the password to access msfrpcd", metavar="opt")
    p.add_option("-S", dest="ssl", help="Disable SSL on the RPC socket", action="store_false", default=True)
    p.add_option("-U", dest="username", help="Specify the username to access msfrpcd", metavar="opt", default="msf")
    p.add_option("-a", dest="server", help="Connect to this IP address", metavar="host", default="127.0.0.1")
    p.add_option("-p", dest="port", help="Connect to the specified port instead of 55552", metavar="opt", default=55552)
    o, a = p.parse_args()
    if o.password is None:
        print('[-] Error: a password must be specified (-P)\n')
        p.print_help()
        exit(-1)
    return o

def convert(data):
    """
    Converts all bytestrings to utf8
    """
    if isinstance(data, bytes):  return data.decode()
    if isinstance(data, list):   return list(map(convert, data))
    if isinstance(data, set):    return set(map(convert, data))
    if isinstance(data, dict):   return dict(map(convert, data.items()))
    if isinstance(data, tuple):  return map(convert, data)
    return data

def encode(data):
    return msgpack.packb(data)

def decode(data):
    return msgpack.unpackb(data)