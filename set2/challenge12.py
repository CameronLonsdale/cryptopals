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

from lantern.util import group

# STATIC_KEY = os.urandom(16)
# UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
# UNKNOWN_STRING = b64decode(UNKNOWN_STRING)

# def enterprise_encryption_function(plaintext: bytearray):
#     """Enterprise Grade Super secure encryption function"""
#     cipher = AES.new(STATIC_KEY, AES.MODE_ECB)
#     plaintext = plaintext + UNKNOWN_STRING
#     return cipher.encrypt(pad(plaintext))

def myround(x, base=16):
    return 0 if x == 0 else int(base * ((x // float(base)) + 1))


def calculate_prefix_length(encrypt, block_size):
    # This will fail if the prefix has two repeating blocks sequentially
    for i in range(0, block_size + 1):
        plaintext = b"A" * i + ((2 * block_size) * b"A")
        ciphertext = group(encrypt(plaintext), block_size)
        for j in range(0, len(ciphertext) - 1):
            if ciphertext[j] == ciphertext[j + 1]:
                print("j is " + str(j))
                print("i is " + str(i))
                if j == 0:
                    return 0
                else:
                    return (j * block_size) - i


def break_ecb(encrypt):
    """Break AES ECB"""

    # Step 1: Detect block size

    # a) Count until a new block is created
    plaintext = b""
    prefix_plus_unknown_plus_padding = len(encrypt(plaintext))
    while len(encrypt(plaintext)) == prefix_plus_unknown_plus_padding:
        plaintext += b"A"

    npadding_bytes = len(plaintext)
    block_size = len(encrypt(plaintext)) - prefix_plus_unknown_plus_padding

    prepend_length = calculate_prefix_length(encrypt, block_size)

    if prepend_length < 0:
        print("Error finding out prefix length, controlled input is not sequential")
        return ''

    unknown_string_length = prefix_plus_unknown_plus_padding - npadding_bytes - prepend_length

    print("Block size: {}".format(block_size))
    print("Prepend string length: {}".format(prepend_length))
    print("Unknown string length: {}".format(unknown_string_length))
    unknown_string_length_rounded = myround(unknown_string_length)
    prepend_length_rounded = myround(prepend_length)


    # Step 2: Determine if ECB or CBC
    plaintext = ((prepend_length_rounded - prepend_length) * b"A") + 2 * (block_size * b"A")
    mode = AES.MODE_ECB if detect_ecb(encrypt(plaintext)) else AES.MODE_CBC
    print("{} mode".format("ECB" if mode == AES.MODE_ECB else "CBC"))

    unknown_string = b""
    for i in range(unknown_string_length_rounded - 1, 0, -1):

        if prepend_length > 0:
            padding = ((prepend_length_rounded - prepend_length) * b"A") + (b"A" * i)
        else:
            padding = (b"A" * i)

        # print(group('abc' + padding.decode('ascii') + "unknown", block_size))

        # print("Total ciphertext " + str(group(encrypt(padding), block_size)))

        # print("rounded is " + str(unknown_string_length_rounded))
        # print("division rounded/blocksize = " + str(unknown_string_length_rounded / block_size))

        # Step 3: Get the oracle
        c1 = encrypt(padding)[prepend_length_rounded:prepend_length_rounded + unknown_string_length_rounded]
        #print(group(c1, block_size))

        # Step 4: Match the oracles
        for byte in range(0, 127):
            plaintext = padding + unknown_string + bytes([byte])
            if encrypt(plaintext)[prepend_length_rounded:prepend_length_rounded + unknown_string_length_rounded] == c1:
                print(unknown_string)
                unknown_string += bytes([byte])
                break

    return unknown_string

#print("AES ECB Unknown string:\n{}".format(break_ecb(enterprise_encryption_function).decode("utf-8")))
