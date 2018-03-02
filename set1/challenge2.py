#!/usr/bin/env python

"""
Fixed XOR
https://cryptopals.com/sets/1/challenges/2
"""

from binascii import hexlify


def xor(a, b):
    """XOR two equal buffers (longest truncated)"""
    return hexlify(bytes([c ^ d for c, d in zip(a, b)])).decode('utf-8')

assert xor(
    bytearray.fromhex('1c0111001f010100061a024b53535009181c'),
    bytearray.fromhex('686974207468652062756c6c277320657965')
) == '746865206b696420646f6e277420706c6179'
