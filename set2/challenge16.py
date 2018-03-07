#!/usr/bin/env python

"""
CBC bitflipping attacks
https://cryptopals.com/sets/2/challenges/16
"""

import os
import html

from Crypto.Cipher import AES
from set1.challenge2 import xor
from challenge9 import pad
from challenge10 import cbc_encrypt, cbc_decrypt
from lantern.util import group

STATIC_KEY = os.urandom(AES.block_size)
STATIC_IV = os.urandom(AES.block_size)


def encrypt(plaintext: str):
    """Enterprise Grade Super secure encryption function"""
    plaintext = plaintext.replace(';', '%3B').replace('=', '%3D')
    plaintext = b"comment1=cooking%20MCs;userdata=" + bytes(plaintext, 'ascii') + b";comment2=%20like%20a%20pound%20of%20bacon"
    print(plaintext)
    return cbc_encrypt(pad(plaintext), STATIC_KEY, STATIC_IV)


def decrypt(ciphertext, iv):
    """Decrypt and check for admin-true"""
    plaintext = cbc_decrypt(ciphertext, STATIC_KEY, iv)
    print(plaintext)
    return bytes(";admin=true;", 'ascii') in plaintext


# We need two blocks, the first to modify such that it flips the bits in the second block


ciphertext = encrypt("XXXXXXXXXXXXXXXX:admin-true")
blocks = group(ciphertext, AES.block_size)
blocks[2][0] ^= (ord(':') ^ ord(';'))
blocks[2][6] ^= (ord('-') ^ ord('='))
blocks = b''.join(blocks)

assert decrypt(blocks, STATIC_IV) is True
