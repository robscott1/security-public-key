import os
import hashlib

from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.Util.py3compat import bchr, bord

E = 65537
RSA_BIT_LENGTH = 2048
MSG = "encrypted message"
SIZE = 16

def main():
    p, q = generate_two_primes()
    key = key_gen(p, q)
    msg = MSG
    IV = os.urandom(16)
    encrypted = encrypt(msg.encode().hex(), key)

    # TODO: Meddle with the encrypted text here
    c_prime = encrypted ^ encrypted

    # TODO: Alice receives tampered transimission, makes sha key out of RSA exchange
    decrypted = decrypt(c_prime, key)
    result = convert_decrypted_to_string(hex(decrypted))

    sha256_hash = bytes(hashlib.sha256(result.encode()).hexdigest().encode())[:AES.block_size]

    #TODO: encrypt, using CBC, a new message using the key exchanged via RSA
    cipher = AES.new(sha256_hash, AES.MODE_CBC, IV)
    c_not_prime = cipher.encrypt(pad(bytes("Malleable!".encode())))

    mallory_key = bytes(hashlib.sha256(result.encode()).hexdigest().encode())[:AES.block_size]

    #TODO: As Mallory, decrypt the ciphertext encrypted via the tampered key
    mallory_aes = AES.new(mallory_key, AES.MODE_CBC, IV)
    print("Message intercepted. Decrypting with Mallory's key...")
    print(unpad(mallory_aes.decrypt(c_not_prime)).decode("utf-8"))


def convert_decrypted_to_string(decrypted):
    hex_string = f"{decrypted}"[2:]
    if hex_string == "0":
        hex_string += "0"
    byte_str = bytes.fromhex(hex_string)
    return byte_str.decode("ASCII")


def encrypt(msg, key):
    msg = int(msg, 16)
    return pow(msg, key.get("public")[0]) % key.get("public")[1]


def decrypt(msg, key):
    return pow(msg, key.get("private")[0], key.get("private")[1])


def key_gen(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = number.inverse(E, phi_n)
    return {
        "public": (E, n),
        "private": (d, n)
    }

def generate_two_primes():
    p = number.getPrime(RSA_BIT_LENGTH, os.urandom)
    q = number.getPrime(RSA_BIT_LENGTH, os.urandom)
    return p, q

def pad(s):
    if len(s) == SIZE:
        return s
    padding_len = SIZE - len(s) % SIZE
    padding = bchr(padding_len) * padding_len
    return s + padding

def unpad(s):
    l = len(s)
    padding_len = bord(s[-1])
    return s[:-padding_len]

if __name__ == "__main__":
    main()