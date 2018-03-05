#!/usr/bin/env python

"""
Implement PKCS#7 padding
https://cryptopals.com/sets/2/challenges/9
"""


def pad(plaintext, block_size=16):
    """PKCS#7 Padding"""
    num_pad = block_size - (len(plaintext) % block_size)
    return plaintext + ''.join(chr(num_pad) for x in range(num_pad))

assert pad("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
