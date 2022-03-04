import os

from Crypto.Util import number
E = 65537
RSA_BIT_LENGTH = 2048
MSG = "encrypted message"

def main():
    p, q = generate_two_primes()
    key = key_gen(p, q)
    msg = MSG
    encrypted = encrypt(msg.encode().hex(), key)
    decrypted = decrypt(encrypted, key)
    result = convert_decrypted_to_string(hex(decrypted))
    print(result)

def convert_decrypted_to_string(decrypted):
    hex_string = f"{decrypted}"[2:]
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




if __name__ == "__main__":
    main()