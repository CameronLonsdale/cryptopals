#!/usr/bin/env python

import os
import random
from Crypto.Cipher import AES
from challenge9 import pad


def encryption_oracle(plaintext: bytearray):
    """Encrypt plaintext with CBC or ECB half the time whilst appending bytes before and after"""
    key = os.urandom(16)
    if bool(random.getrandbits(1)):
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = os.urandom(random.randint(5, 10)) + plaintext + os.urandom(random.randint(5, 10))
    return cipher.encrypt(pad(plaintext))

print(encryption_oracle(b"test"))


# DO AN EXPERIMENT FOR HOW GOOD TO DETECTION IS
