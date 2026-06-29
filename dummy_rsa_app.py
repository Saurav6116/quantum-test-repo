import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_post_quantum_keys():
    print("[+] Generating FIPS 203 (ML-KEM) Post-Quantum keys...")
    # Initialize the NIST approved Kyber KEM
    kem = oqs.KeyEncapsulation('Kyber512')
    public_key = kem.generate_keypair()
    return kem, public_key

def encrypt_data(message, public_key):
    # 1. Encapsulate a shared secret using the server's public key
    client_kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = client_kem.encap_secret(public_key)
    
    # 2. Use the ML-KEM shared secret (32 bytes) as an AES-256 key to encrypt the actual data
    aesgcm = AESGCM(shared_secret)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode('utf8'), None)
    
    return ciphertext, nonce, encrypted_message

if __name__ == "__main__":
    # --- SERVER SIDE ---
    server_kem, pub_key = generate_post_quantum_keys()
    
    # --- CLIENT SIDE ---
    print("[+] Encrypting payload using KEM + AES hybrid...")
    kem_ciphertext, nonce, enc_msg = encrypt_data("Super Secret Customer Data", pub_key)
    print(f"[*] Data Encrypted securely: {enc_msg.hex()[:30]}...")
    
    # --- DECRYPTION PROOF ---
    # Server decapsulates the shared secret using its private KEM
    server_secret = server_kem.decap_secret(kem_ciphertext)
    
    # Server uses the secret to decrypt the AES payload
    server_aes = AESGCM(server_secret)
    decrypted_msg = server_aes.decrypt(nonce, enc_msg, None)
    
    print(f"\n[🚀 SUCCESS] Server successfully decrypted: '{decrypted_msg.decode('utf8')}'")
