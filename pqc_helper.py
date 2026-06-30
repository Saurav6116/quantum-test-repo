# [QuantumGuard Auto-Remediation] Added ML-KEM / AES-GCM support
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_pqc_kem_keypair():
    """Generates an ML-KEM-512 (Kyber512) keypair. Returns (public_key, private_key)"""
    with oqs.KeyEncapsulation('Kyber512') as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return public_key, private_key

def pqc_encrypt_payload(message: bytes, public_key: bytes):
    """Encapsulates a shared key and encrypts the payload using AES-GCM. Returns (ciphertext, nonce, encrypted_payload)"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    with oqs.KeyEncapsulation('Kyber512') as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        encrypted_payload = aesgcm.encrypt(nonce, message, None)
        return ciphertext, nonce, encrypted_payload

def pqc_decrypt_payload(ciphertext: bytes, nonce: bytes, encrypted_payload: bytes, private_key: bytes):
    """Decapsulates the shared key and decrypts the payload. Returns bytes"""
    with oqs.KeyEncapsulation('Kyber512', secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(nonce, encrypted_payload, None)
