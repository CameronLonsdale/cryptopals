#!/usr/bin/env python3

"""
ECB cut-and-paste
https://cryptopals.com/sets/2/challenges/13
"""

import html
import os

from Crypto.Cipher import AES
from challenge9 import pad
from collections import OrderedDict
from lantern.util import group

TEST_FORM = 'foo=bar&baz=qux&zap=zazzle'
TEST_DICT = OrderedDict([('foo', 'bar'), ('zap', 'zazzle'), ('baz', 'qux')])


def form_to_dict(urlencoded: str):
    """Decode a form of the structure foo=bar&baz=qux&zap=zazzle"""
    return {obj.split('=')[0]: obj.split('=')[1] for obj in urlencoded.split('&')}

assert form_to_dict(TEST_FORM) == TEST_DICT


def dict_to_form(obj: dict):
    """Encode a form to dict"""
    return '&'.join('{0}={1}'.format(k, v) for k, v in obj.items())


assert form_to_dict(dict_to_form(TEST_DICT)) == TEST_DICT


def profile_for(email: str):
    """Generate profile for email"""
    return OrderedDict([('email', html.escape(email)), ('uid', 10), ('role', 'user')])

assert profile_for("foo@bar.com") == OrderedDict([('email', 'foo@bar.com'), ('uid', 10), ('role', 'user')])


# Now, two more easy functions. Generate a random AES key, then:

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

encrypted_profile = cipher.encrypt(pad(bytes(dict_to_form(profile_for("foo@bar.com")), 'ascii')))


# Tamper the block to make the ciphertext read role=admin
plaintext_profile = pad(bytes(dict_to_form(profile_for("myawesome@fuck.com")), 'ascii'))
encrypted_profile = cipher.encrypt(plaintext_profile)
print("Profile: {0}, Encrypted Profile: {1}".format(plaintext_profile, encrypted_profile))

#email=foo@bar.co maaaaaa&uid=10& role=user 7 padding bytes
#email=foo@bar.co maaaaaa&uid=10& role=admin 6 padding bytes

replacement_block = b"role=admin" + b"\x06"*6
encrypted_replacement_block = cipher.encrypt(replacement_block)

blocks = group(encrypted_profile, AES.block_size)
blocks[-1] = encrypted_replacement_block

tampered_cipertext = b''.join(blocks)
print(tampered_cipertext)

print(cipher.decrypt(tampered_cipertext))