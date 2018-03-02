#!/usr/bin/env python

"""
Implement repeating-key XOR
https://cryptopals.com/sets/1/challenges/5
"""

from challenge2 import xor

plaintext = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""


def repeating_xor(key: bytearray, plaintext: bytearray):
    """Encrypt plaintext using key"""
    key_repeated = bytearray(key * round(len(plaintext) / len(key)))
    return xor(key_repeated, plaintext)

assert repeating_xor(bytearray("ICE", 'ascii'), bytearray(plaintext, 'ascii')) == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
