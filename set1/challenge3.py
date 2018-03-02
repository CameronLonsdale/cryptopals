#!/usr/bin/env python

"""
Single-byte XOR cipher
https://cryptopals.com/sets/1/challenges/3
"""

import binascii
import string

from challenge2 import xor
from lantern.structures import Decryption
from lantern.fitness import english
from lantern.util import remove

MAX_BYTE = 2**8 - 1


def xor_brute(ciphertext):
    """
    Bruteforce XOR keys to decrypt ciphertext
    We assume the plaintext is english text
    """
    decryptions = []

    for key in range(MAX_BYTE):
        key_extended = bytearray([key] * len(ciphertext))

        try:
            plaintext = binascii.unhexlify(xor(ciphertext, key_extended)).decode('utf-8')
        except UnicodeDecodeError:
            continue
        else:
            score = english.quadgrams(plaintext)
            decryption = Decryption(plaintext, key, score)
            # This is a (flaw?) in lantern that punct + whitespace is removed when scoring, however because the score
            # calculation is based on length, this means that incorrect strings full of punctuation can out score
            # correct decryptions with mostly letters. Therefore, we modify the score by how many characters were
            # removed during scoring. I should probably fix this in latern
            decryption.score /= len(remove(plaintext, string.whitespace + string.punctuation)) / len(plaintext)
            decryptions.append(decryption)

    return sorted(decryptions, reverse=True)

decryptions = xor_brute(bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
assert decryptions[0].plaintext == "Cooking MC's like a pound of bacon"
