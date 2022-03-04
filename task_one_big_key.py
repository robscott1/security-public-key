from task_one import Party



def generate_private_keys(party1: Party, party2: Party):
    party1.generate_private_key(party2.get_public_key())
    party2.generate_private_key(party1.get_public_key())


def assure_same_priv_key(p1, p2):
    if p1._private_key == p2._private_key:
        print("Private keys match...")
    else:
        print("ERROR: private keys do not match...")


def mitm_generate_private_keys(party1: Party, party2: Party, mitm: Party):
    party1.generate_private_key(mitm.get_public_key())
    party2.generate_private_key(mitm.get_public_key())


def main():
    P = f"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6" \
        f"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" \
        f"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70" \
        f"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" \
        f"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" \
        f"DF1FB2BC2E4A4371"

    G = f"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F" \
        f"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213" \
        f"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1" \
        f"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" \
        f"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" \
        f"855E6EEB22B3B2E5"


    P = int(P, 16)
    G = int(G, 16)
    alice = Party(P, G, 6)
    bob = Party(P, G, 15)
    mallory = Party(P, G, 7)

    # MITM key public key exchange
    mitm_generate_private_keys(alice, bob, mallory)

    encrypted_message = alice.encrypt_message("plaintext message")

    # Man in the middle eavesdrop
    mallory.generate_private_key(alice.get_public_key())
    intercepted_message = mallory.decrypt_message(encrypted_message)
    print(f"Intercepted message: {intercepted_message.decode('utf-8')}")



if __name__ == "__main__":
    main()
