#!/usr/bin/env python

"""
The CBC padding oracle
https://cryptopals.com/sets/3/challenges/17
"""

import base64
import random
import os

from Crypto.Cipher import AES

from typing import Tuple
from set2.challenge9 import pad
from set2.challenge15 import validate_padding
from set2.challenge10 import cbc_encrypt, cbc_decrypt


ENCRYPTION_KEY = os.urandom(AES.block_size)


def get_token() -> Tuple[str, str]:
    """AES CBC Encrypt a random string using a static key and variable IV"""
    strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    plaintext =  base64.b64decode(random.choice(strings))
    iv = os.urandom(AES.block_size)
    print(pad(plaintext))
    return cbc_encrypt(plaintext, ENCRYPTION_KEY, iv), iv

def validate_token(ciphertext, iv):
    plaintext = bytes(cbc_decrypt(ciphertext, ENCRYPTION_KEY, iv))
    print(plaintext)
    try: 
        validate_padding(plaintext)
        return True
    except:
        return False


# ciphertext, iv = get_token()
# print(validate_token(ciphertext, iv))
# print(base64.b64encode(ciphertext))

def crack():
    # Plaintext
    #b'000009ith my rag-top down so my hair can blow\x03\x03\x03'
    # Ciphertext
    ciphertext = base64.b64decode("NL+QJ7R7l10wMiW0kjgKHfvUI8TlekUFyS1VPFSNAkMZsVOmpZotgN9Y0FQQm6Z8")
    iv = bytearray(b"\x00" * 16)
    print(validate_token(ciphertext, iv))

#crack()

