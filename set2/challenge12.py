#!/usr/bin/env python

"""
Byte-at-a-time ECB decryption (Simple)
https://cryptopals.com/sets/2/challenges/12
"""

import os
from base64 import b64decode
from Crypto.Cipher import AES
from challenge9 import pad
from set1.challenge8 import detect_ecb

STATIC_KEY = os.urandom(16)
UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
UNKNOWN_STRING = b64decode(UNKNOWN_STRING)

def enterprise_encryption_function(plaintext: bytearray):
    """Enterprise Grade Super secure encryption function"""
    cipher = AES.new(STATIC_KEY, AES.MODE_ECB)
    plaintext = plaintext + UNKNOWN_STRING
    return cipher.encrypt(pad(plaintext))

def break_ecb():
    """Break AES ECB"""

    # Step 1: Detect block size

    # a) Find how many padding bytes
    plaintext = b"A"
    length = len(enterprise_encryption_function(plaintext))
    while len(enterprise_encryption_function(plaintext)) == length:
        plaintext += b"A"

    # b) find out how many bytes are in a block
    npadding_bytes = len(plaintext)
    length = len(enterprise_encryption_function(plaintext))
    while len(enterprise_encryption_function(plaintext)) == length:
        plaintext += b"A"

    block_size = len(plaintext) - npadding_bytes
    print("Block size: {}".format(block_size))

    # c) find out how long the unknown string is
    unknown_string_length = len(enterprise_encryption_function(b''))
    print("Unknown string length: {}".format(unknown_string_length))
    unknown_string_length_rounded = int(((unknown_string_length / block_size) + 1) * block_size)

    # Step 2: Determine if ECB or CBC
    plaintext = 2 * (block_size * b"A")
    mode = AES.MODE_ECB if detect_ecb(enterprise_encryption_function(plaintext)) else AES.MODE_CBC
    print("{} mode".format("ECB" if mode == AES.MODE_ECB else "CBC"))

    unknown_string = b""
    for i in range(unknown_string_length_rounded - 1, 0, -1):
        padding = b"A" * i

        # Step 3: Get the oracle
        c1 = enterprise_encryption_function(padding)[:unknown_string_length_rounded]
        print(c1)

        # Step 4: Match the oracles
        for byte in range(0, 127):
            plaintext = padding + unknown_string + bytes([byte])
            print(plaintext)
            if enterprise_encryption_function(plaintext)[:unknown_string_length_rounded] == c1:
                unknown_string += bytes([byte])
                break

    return unknown_string

print("AES ECB Unknown string:\n{}".format(break_ecb().decode("utf-8")))
