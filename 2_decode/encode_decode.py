#!/usr/bin/env python3
"""
Encode or Decode between formats.
"""
import json
import yaml
import xml
import brotli
import zlib
import urllib.parse
import binascii
from Crypto.Hash import MD5, SHA256
from base64 import b64encode, b64decode
from math import ceil as ceil

import time


def string2bytes(item):
    """
    Converts string to bytes format.
    'A' -> b'A'
    """
    if type(item) == str:
        return bytes(item, 'utf-8')
    else:
        return "Wrong data type expected string, received %s" % str(type(item).__name__)


def string2hex(item):
    """
    Converts string to hex string format.
    'A' -> '41'
    """
    formatted_item = hash_format(item)
    if formatted_item:
        return binascii.hexlify(formatted_item)
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def hex2string(item):
    """
    Converts hex string to string format.
    '41' -> 'A'
    """
    formatted_item = hash_format(item)
    if formatted_item:
        return binascii.unhexlify(formatted_item)
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def hash_format(item):
    """
    Converts the input to bytes format.
    """
    if type(item) == str:
        return string2bytes(item)
    elif type(item) == bytes:
        return item
    else:
        return None


def string2md5(item):
    """
    Computes the MD5 hash from the input.
    """
    hash_obj = MD5.new()
    formatted_item = hash_format(item)
    if formatted_item:
        hash_obj.update(formatted_item)
        return hash_obj.hexdigest()
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def string2sha256(item):
    """
    Computes the SHA256 hash from the input.
    """
    hash_obj = SHA256.new()
    formatted_item = hash_format(item)
    if formatted_item:
        hash_obj.update(formatted_item)
        return hash_obj.hexdigest()
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def string2b64(item):
    """
    Encodes the input in base64.
    'Spartan!!' -> 'U3BhcnRhbiEh'
    """
    formatted_item = hash_format(item)
    if formatted_item:
        return b64encode(formatted_item)
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def b642string(item):
    """
    Decodes the input from base64.
    'U3BhcnRhbiEh' -> 'Spartan!!'
    """
    formatted_item = hash_format(item)
    if formatted_item:
        return b64decode(formatted_item)
    else:
        return "Wrong data type expected string or byte, received %s" %\
               str(type(item).__name__)


def reverse(item):
    """
    Reverses the input.
    'ABC' -> 'CBA'
    """
    return item[::-1]


def string2brotli(item):
    """
    Compress string using brotli.
    'A'*100 -> '\x1bc\x00\xf8%\x82\x02\xb1@\xa0\x03'
    """
    formatted_item = hash_format(item)
    return brotli.compress(formatted_item)


def brotli2string(item):
    """
    Decompress brotli into string.
     '\x1bc\x00\xf8%\x82\x02\xb1@\xa0\x03' -> 'A'*100
    """
    formatted_item = hash_format(item)
    return brotli.decompress(formatted_item)


def string2gzip(item):
    """
    Compress string using gzip.
    'A' -> b'x\x9cs\x04\x00\x00B\x00B'
    """
    formatted_item = hash_format(item)
    return zlib.compress(formatted_item)


def gzip2string(item):
    """
    Decompress gzip into string.
    b'x\x9cs\x04\x00\x00B\x00B' -> 'A'
    """
    formatted_item = hash_format(item)
    return zlib.decompress(formatted_item)


def string2urlencode(item):
    """
    URL encode string.
    'A B/' -> 'A+B%2F'
    """
    formatted_item = hash_format(item)
    return urllib.parse.quote_plus(formatted_item)


def urldecode2string(item):
    """
    Decode URL encoded into string.
    'A+B%2F' -> 'A B/'
    """
    formatted_item = hash_format(item)
    return urllib.parse.unquote_plus(formatted_item)


def urldecode2bytes(item):
    """
    Decode URL encoded into bytes.
    'A+B%2F' -> b'A+B/'
    """
    formatted_item = hash_format(item)
    return urllib.parse.unquote_plus(formatted_item)


def json2yaml(item):
    """
    Convert JSON into YAML.
    '{"a": {"b": 1, "c": [2, 3]}}' ->  'a:\n  b: 1\n  c:\n  - 2\n  - 3\n'
    """
    formatted_item = hash_format(item)
    return yaml.dump(json.loads(formatted_item))


def yaml2json(item, Loader=yaml.SafeLoader):
    """
    Convert YAML into JSON.
    'a:\n  b: 1\n  c:\n  - 2\n  - 3\n' -> '{"a": {"b": 1, "c": [2, 3]}}'
    """
    formatted_item = hash_format(item)
    return json.dumps(yaml.load(formatted_item, Loader=Loader))


def stringxor(item, key):
    """
    String XOR with key, if the key is shorter it will be repeated multiple
    times to match the length of the payload.
    'ABC','A' -> '\x00\x03\x02'
    '\x00\x03\x02','A' -> 'ABC'
    """
    pos = 0
    payload = list()
    key_stream = list()
    key_string = key * ceil(len(item) / len(key))
    while pos < len(item):
        payload.append(item[pos])
        key_stream.append(key_string[pos])
        pos += 1
    xor = [chr(ord(p) ^ ord(k)) for p, k in zip(payload, key_stream)]
    return ''.join(xor)