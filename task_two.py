from task_one import Party

# PART 2: changing G to P, P - 1, or 1 will still compromise encryption
P = 23
G = 5



def generate_private_keys(party1: Party, party2: Party):
    party1.generate_private_key(party2.get_public_key())
    party2.generate_private_key(party1.get_public_key())


def assure_same_priv_key(p1, p2):
    if p1._private_key == p2._private_key:
        print("Private keys match...")
    else:
        print("ERROR: private keys do not match...")

"""
Use this function to generate private keys when demonstrating
Man in the Middle attack
"""
def mitm_generate_private_keys(party1: Party, party2: Party, mitm: Party):
    party1.generate_private_key(mitm.get_public_key())
    party2.generate_private_key(mitm.get_public_key())


def main():
    alice = Party(P, G, 6)
    bob = Party(P, G, 15)
    mallory = Party(P, G, 7)

    # N using MITM, tampering with generator value instead
    mitm_generate_private_keys(alice, bob, mallory)

    encrypted_message = alice.encrypt_message("plaintext message")

    # Man in the middle eavesdrop
    mallory.generate_private_key(alice.get_public_key())
    intercepted_message = mallory.decrypt_message(encrypted_message)
    print(f"Intercepted message: {intercepted_message.decode('utf-8')}")



if __name__ == "__main__":
    main()
