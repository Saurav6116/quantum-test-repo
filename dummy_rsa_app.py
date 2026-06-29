import rsa

def generate_legacy_keys():
    # Vulnerable Harvest Now, Decrypt Later cryptography
    print("Generating classic RSA keys...")
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

def encrypt_data(message, pub_key):
    # This data could be stolen today and decrypted by a quantum computer in 5 years
    encrypted = rsa.encrypt(message.encode('utf8'), pub_key)
    return encrypted

if __name__ == "__main__":
    pub, priv = generate_legacy_keys()
    cipher = encrypt_data("Super Secret Customer Data", pub)
    print("Data Encrypted successfully.")
