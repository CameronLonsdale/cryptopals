#!/usr/bin/env python

"""
Convert hex to base64
https://cryptopals.com/sets/1/challenges/1
"""

from base64 import b64encode
import itertools
from lantern.util import group


def hex2base64(hex_string):
    """Encode a hex string into base64"""
    return b64encode(bytearray.fromhex(hex_string)).decode('utf-8')


def hex2base64_custom(hex_string):
    """
    Encode a hex string into base64 without using the base64 library
    https://tools.ietf.org/html/rfc3548.html#section-3
    """
    alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

    # Split hex string into bytes, then group into threes
    bytes = [int(byte, 16) for byte in group(hex_string, 2)]
    triplets = group(bytes, 3)

    # Pack 24 bits together and convert into a bit string
    packed = [format(int.from_bytes(triplet, byteorder='big'), str(len(triplet) * 8) + 'b') for triplet in triplets]

    # Split the bit string into groups of 6 bits
    input_group = [group(bits, 6) for bits in packed]

    # Add padding bits if the group is less than 24 bits long
    padding = 4 - len(input_group[-1])
    if padding:
        input_group[-1].extend([format(64, 'b')] * padding)

    # Flatten the list and convert to integer indexes
    input_group = list(itertools.chain.from_iterable(input_group))
    indexes = [int(index, 2) for index in input_group]

    return ''.join(alphabet[index] for index in indexes)

string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

assert hex2base64(string) == result
assert hex2base64_custom(string) == result

assert hex2base64('9090') == hex2base64_custom('9090')
assert hex2base64('90') == hex2base64_custom('90')
