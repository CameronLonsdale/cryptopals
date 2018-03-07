#!/usr/bin/env python

"""
PKCS#7 padding validation
https://cryptopals.com/sets/2/challenges/15
"""


def find_padding_character(plaintext):
    # Can only be from 1 to 15
    for byte in range(1, 16):
        start = plaintext.find(chr(byte))
        if start > 0:
            # Check that all characters after it are the same
            if all(plaintext[i] == chr(byte) for i in range(start, len(plaintext))):
                return start

    return -1


def validate_padding(text, block_size=16):
    start = find_padding_character(text)
    padding_length = len(text) - start
    if text[start] == chr(padding_length):
        return text[:start]

    raise Exception()

assert validate_padding("ICE ICE BABY\x04\x04\x04\x04") == "ICE ICE BABY"

try:
    validate_padding("ICE ICE BABY\x05\x05\x05\x05")
except Exception:
    print("Invalid Padding")

try:
    validate_padding("ICE ICE BABY\x01\x02\x03\x04")
except Exception:
    print("Invalid Padding")
