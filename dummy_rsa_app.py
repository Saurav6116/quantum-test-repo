import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_post_quantum_keys():
    kem = oqs.KeyEncapsulation('Kyber512')
    public_key = kem.generate_keypair()
    return kem, public_key

def encrypt_data(message, public_key):
    client_kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = client_kem.encap_secret(public_key)
    
    aesgcm = AESGCM(shared_secret)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode('utf8'), None)
    
    return ciphertext, nonce, encrypted_message

if __name__ == "__main__":
    server_kem, pub_key = generate_post_quantum_keys()
    kem_ciphertext, nonce, enc_msg = encrypt_data("Test Message", pub_key)
    server_secret = server_kem.decap_secret(kem_ciphertext)
    server_aes = AESGCM(server_secret)
    decrypted_msg = server_aes.decrypt(nonce, enc_msg, None)
    assert decrypted_msg.decode('utf8') == "Test Message"
