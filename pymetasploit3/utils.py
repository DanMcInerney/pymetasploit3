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
    p.add_option("-p", dest="port", help="Connect to the specified port instead of 55553", metavar="opt", default=55553)
    o, a = p.parse_args()
    if o.password is None:
        print('[-] Error: a password must be specified (-P)\n')
        p.print_help()
        exit(-1)
    return o


def try_convert(data, encodings, decode_error_handling):
    """Tries to decode the data with all the specified encodings, the order is perserved.

    Parameters
    ----------
    data : bytes
    encodings : List[str]
    decode_error_handling: str

    Returns
    -------
    Tuple[str, str]
        The actual decoded data
        The encoding used to decode the data
    """

    default_encoding: str = encodings[-1]
    # Loop over all the encodings but the last one, which is the default one
    for encoding in encodings[:-1]:
        try:
            # We want it to be strict because we need to find the proper encoding
            decoded: str = data.decode(encoding=encoding, errors="strict")
            return decoded, encoding
        except Exception:
            pass

    # If we haven't returned, try with the last one (default) and don't catch the exception
    # Here and only here we use the parameter decode_error_handling which is controlled by the user of the library
    return data.decode(encoding=default_encoding, errors=decode_error_handling), default_encoding

def convert(data, encodings, decode_error_handling):
    """Converts all bytestrings to utf8

    Parameters
    ----------
    data : Any
    encodings : List[str]
    decode_error_handling : str

    Returns
    -------
    Any
    """
    if isinstance(data, bytes):  return try_convert(data, encodings=encodings, decode_error_handling=decode_error_handling)[0]
    if isinstance(data, list):   return list(map(lambda iter: convert(iter, encodings=encodings, decode_error_handling=decode_error_handling), data))
    if isinstance(data, set):    return set(map(lambda iter: convert(iter, encodings=encodings, decode_error_handling=decode_error_handling), data))
    if isinstance(data, dict):   return dict(map(lambda iter: convert(iter, encodings=encodings, decode_error_handling=decode_error_handling), data.items()))
    if isinstance(data, tuple):  return map(lambda iter: convert(iter, encodings=encodings, decode_error_handling=decode_error_handling), data)
    return data

def encode(data):
    return msgpack.packb(data)

def decode(data):
    return msgpack.unpackb(data, strict_map_key=False)