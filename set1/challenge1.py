"""
Convert hex to base64
https://cryptopals.com/sets/1/challenges/1
"""

from base64 import b64encode


def hex2base64(hex_string):
    """Encode a hex string into base64"""
    return b64encode(bytearray.fromhex(hex_string))


string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
assert hex2base64(string) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
