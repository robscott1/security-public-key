import json
from base64 import b64encode
from hashlib import sha256
from os import urandom
from random import Random

from Crypto.Cipher import AES
from Crypto.Util.py3compat import bord, bchr

SIZE = 16
P = 23
G = 5

# TODO: how to work this without global IV
IV = urandom(16)


class Party:

    def __init__(self, p, g, x):
        self.key = None
        self.p = p
        self.g = g
        self.x = x
        self.generate_public_key()
        self._private_key = None

    def generate_public_key(self):
        key = pow(self.g, self.x) % self.p
        self.key = key

    def get_public_key(self):
        return self.key

    def generate_private_key(self, other_party_pub_key):
        key = sha256((str(pow(other_party_pub_key, self.x) % self.p)) \
                     .encode()).hexdigest()
        self._private_key = bytes(key.encode())[:16]

    def encrypt_message(self, msg):
        key = self._private_key
        cipher = AES.new(key, AES.MODE_CBC, IV)
        prepped_message = self.pad(bytes(msg.encode()))
        result = cipher.encrypt(prepped_message)
        return result

    def decrypt_message(self, msg):
        key = self._private_key
        cipher = AES.new(key, AES.MODE_CBC, IV)
        result = cipher.decrypt(msg)
        return self.unpad(result)


    def pad(self, s):
        if len(s) == SIZE:
            return s
        padding_len = SIZE - len(s) % SIZE
        padding = bchr(padding_len) * padding_len
        return s + padding

    def unpad(self, s):
        l = len(s)
        padding_len = bord(s[-1])
        return s[:-padding_len]


def generate_private_keys(party1: Party, party2: Party):
    party1.generate_private_key(party2.get_public_key())
    party2.generate_private_key(party1.get_public_key())


def assure_same_priv_key(p1, p2):
    if p1._private_key == p2._private_key:
        print("Private keys match...")
    else:
        print("ERROR: private keys do not match...")


def main():
    alice = Party(P, G, 6)
    bob = Party(P, G, 15)

    generate_private_keys(alice, bob)
    assure_same_priv_key(alice, bob)

    encrypted_message = alice.encrypt_message("plaintext message")
    decrypted_message = bob.decrypt_message(encrypted_message)
    print(decrypted_message.decode("utf-8"))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
