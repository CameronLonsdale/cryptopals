#!/usr/bin/env python

import os
from base64 import b64decode
import random
from Crypto.Cipher import AES
from challenge9 import pad

from challenge12 import break_ecb

"""
Byte-at-a-time ECB decryption (Harder)
https://cryptopals.com/sets/2/challenges/14
"""

STATIC_KEY = os.urandom(16)
UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
UNKNOWN_STRING = b64decode(UNKNOWN_STRING)

PREPENDED_STRING = b''.join([bytes([random.randint(0, 255)]) for i in range(random.randint(5, 32))])

def enterprise_encryption_function(plaintext: bytearray):
    """Enterprise Grade Super secure encryption function"""
    cipher = AES.new(STATIC_KEY, AES.MODE_ECB)
    plaintext = PREPENDED_STRING + plaintext + UNKNOWN_STRING
    return cipher.encrypt(pad(plaintext))


# |p | round up   | length of unknown string (rounded)                               |
# abcaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaau

# abcAAAAAAAAAAAAA AAAAAAAAAAAAAAAA aaaaaaaaaaaaaaaa

print(break_ecb(enterprise_encryption_function))
