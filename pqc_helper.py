# [QuantumGuard Auto-Remediation] Added ML-KEM / AES-GCM support
import os
import oqs
import json
import base64
import hashlib
import sys
from types import ModuleType
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Script-level configuration:
# Set to True to use NIST-recommended Dual-Hybrid (RSA + ML-KEM)
# Set to False to use Pure Post-Quantum Cryptography (ML-KEM only)
USE_HYBRID = True

def pack_ciphertext(kem_ct, rsa_ct, nonce, aes_ct):
    if rsa_ct is not None:
        # Hybrid Mode: "HYB" header
        return b"HYB" + len(kem_ct).to_bytes(4, 'big') + len(rsa_ct).to_bytes(4, 'big') + len(nonce).to_bytes(4, 'big') + kem_ct + rsa_ct + nonce + aes_ct
    else:
        # Pure PQC Mode: "PQC" header
        return b"PQC" + len(kem_ct).to_bytes(4, 'big') + len(nonce).to_bytes(4, 'big') + kem_ct + nonce + aes_ct

def unpack_ciphertext(data):
    if data.startswith(b"HYB"):
        ptr = 3
        len_kem = int.from_bytes(data[ptr:ptr+4], 'big')
        ptr += 4
        len_rsa = int.from_bytes(data[ptr:ptr+4], 'big')
        ptr += 4
        len_nonce = int.from_bytes(data[ptr:ptr+4], 'big')
        ptr += 4
        
        kem_ct = data[ptr:ptr+len_kem]
        ptr += len_kem
        rsa_ct = data[ptr:ptr+len_rsa]
        ptr += len_rsa
        nonce = data[ptr:ptr+len_nonce]
        ptr += len_nonce
        aes_ct = data[ptr:]
        return kem_ct, rsa_ct, nonce, aes_ct
    elif data.startswith(b"PQC"):
        ptr = 3
        len_kem = int.from_bytes(data[ptr:ptr+4], 'big')
        ptr += 4
        len_nonce = int.from_bytes(data[ptr:ptr+4], 'big')
        ptr += 4
        
        kem_ct = data[ptr:ptr+len_kem]
        ptr += len_kem
        nonce = data[ptr:ptr+len_nonce]
        ptr += len_nonce
        aes_ct = data[ptr:]
        return kem_ct, None, nonce, aes_ct
    else:
        raise ValueError("Invalid or unrecognized ciphertext format")

def generate_pqc_kem_keypair(*args, **kwargs):
    """Generates keypair. Returns (public_key, private_key)"""
    if USE_HYBRID:
        # 1. Generate Classical RSA Key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_priv_bytes = rsa_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        rsa_pub_bytes = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 2. Generate Post-Quantum ML-KEM Key
        with oqs.KeyEncapsulation('Kyber512') as kem:
            kem_pub_bytes = kem.generate_keypair()
            kem_priv_bytes = kem.export_secret_key()

        # 3. Combine and serialize
        pub_dict = {
            "rsa": base64.b64encode(rsa_pub_bytes).decode('ascii'),
            "kem": base64.b64encode(kem_pub_bytes).decode('ascii')
        }
        priv_dict = {
            "rsa": base64.b64encode(rsa_priv_bytes).decode('ascii'),
            "kem": base64.b64encode(kem_priv_bytes).decode('ascii'),
            "kem_pub": base64.b64encode(kem_pub_bytes).decode('ascii')
        }
        return json.dumps(pub_dict).encode('utf-8'), json.dumps(priv_dict).encode('utf-8')
    else:
        # Pure PQC mode
        with oqs.KeyEncapsulation('Kyber512') as kem:
            kem_pub_bytes = kem.generate_keypair()
            kem_priv_bytes = kem.export_secret_key()
        pub_dict = {
            "kem": base64.b64encode(kem_pub_bytes).decode('ascii')
        }
        priv_dict = {
            "kem": base64.b64encode(kem_priv_bytes).decode('ascii'),
            "kem_pub": base64.b64encode(kem_pub_bytes).decode('ascii')
        }
        return json.dumps(pub_dict).encode('utf-8'), json.dumps(priv_dict).encode('utf-8')

def pqc_encrypt_payload(message: bytes, public_key: bytes):
    """Encrypts message using either Dual-Hybrid or pure ML-KEM based on USE_HYBRID setting. Returns tuple of components."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    pub_dict = json.loads(public_key.decode('utf-8'))
    kem_pub_bytes = base64.b64decode(pub_dict["kem"])

    if "rsa" in pub_dict and USE_HYBRID:
        rsa_pub_bytes = base64.b64decode(pub_dict["rsa"])
        rsa_pub = serialization.load_der_public_key(rsa_pub_bytes)

        # Generate ML-KEM shared secret
        with oqs.KeyEncapsulation('Kyber512') as kem:
            kem_ciphertext, shared_secret_pqc = kem.encap_secret(kem_pub_bytes)

        # Generate Classical secret and wrap with RSA
        shared_secret_classical = os.urandom(32)
        rsa_ciphertext = rsa_pub.encrypt(
            shared_secret_classical,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Combine both secrets to form the AES key
        combined_key = hashlib.sha256(shared_secret_pqc + shared_secret_classical).digest()

        # Encrypt bulk payload using AES-GCM
        aesgcm = AESGCM(combined_key)
        nonce = os.urandom(12)
        encrypted_payload = aesgcm.encrypt(nonce, message, None)

        return kem_ciphertext, rsa_ciphertext, nonce, encrypted_payload
    else:
        # Pure PQC mode
        with oqs.KeyEncapsulation('Kyber512') as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(kem_pub_bytes)
            aesgcm = AESGCM(shared_secret)
            nonce = os.urandom(12)
            encrypted_payload = aesgcm.encrypt(nonce, message, None)
            return kem_ciphertext, nonce, encrypted_payload

def pqc_decrypt_payload(*args):
    """
    Decrypts payload using either Dual-Hybrid or pure ML-KEM based on input parameters.
    Supports both single-bytes ciphertext and unpacked tuple formats.
    """
    private_key = args[-1]

    # Handle packed ciphertext format (2 arguments)
    if len(args) == 2 and isinstance(args[0], bytes):
        ciphertext_data = args[0]
        priv_dict = json.loads(private_key.decode('utf-8'))
        kem_ciphertext, rsa_ciphertext, nonce, encrypted_payload = unpack_ciphertext(ciphertext_data)

        if rsa_ciphertext is not None:
            # Dual-Hybrid Mode
            rsa_priv_bytes = base64.b64decode(priv_dict["rsa"])
            kem_priv_bytes = base64.b64decode(priv_dict["kem"])
            rsa_priv = serialization.load_der_private_key(rsa_priv_bytes, password=None)

            with oqs.KeyEncapsulation('Kyber512', secret_key=kem_priv_bytes) as kem:
                shared_secret_pqc = kem.decap_secret(kem_ciphertext)

            shared_secret_classical = rsa_priv.decrypt(
                rsa_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            combined_key = hashlib.sha256(shared_secret_pqc + shared_secret_classical).digest()
            aesgcm = AESGCM(combined_key)
            return aesgcm.decrypt(nonce, encrypted_payload, None)
        else:
            # Pure PQC Mode
            kem_priv_bytes = base64.b64decode(priv_dict["kem"])
            with oqs.KeyEncapsulation('Kyber512', secret_key=kem_priv_bytes) as kem:
                shared_secret = kem.decap_secret(kem_ciphertext)
                aesgcm = AESGCM(shared_secret)
                return aesgcm.decrypt(nonce, encrypted_payload, None)

    # Backward compatibility: handle unpacked hybrid (5 arguments)
    elif len(args) == 5:
        kem_ciphertext, rsa_ciphertext, nonce, encrypted_payload = args[0], args[1], args[2], args[3]
        priv_dict = json.loads(private_key.decode('utf-8'))
        rsa_priv_bytes = base64.b64decode(priv_dict["rsa"])
        kem_priv_bytes = base64.b64decode(priv_dict["kem"])

        rsa_priv = serialization.load_der_private_key(rsa_priv_bytes, password=None)
        with oqs.KeyEncapsulation('Kyber512', secret_key=kem_priv_bytes) as kem:
            shared_secret_pqc = kem.decap_secret(kem_ciphertext)

        shared_secret_classical = rsa_priv.decrypt(
            rsa_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        combined_key = hashlib.sha256(shared_secret_pqc + shared_secret_classical).digest()
        aesgcm = AESGCM(combined_key)
        return aesgcm.decrypt(nonce, encrypted_payload, None)

    # Backward compatibility: handle unpacked pure PQC (4 arguments)
    elif len(args) == 4:
        kem_ciphertext, nonce, encrypted_payload = args[0], args[1], args[2]
        with oqs.KeyEncapsulation('Kyber512', secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)
            aesgcm = AESGCM(shared_secret)
            return aesgcm.decrypt(nonce, encrypted_payload, None)
    else:
        raise ValueError(f"Invalid arguments for decryption: {len(args)}")


# --- Emulation interfaces for classical 'rsa' library ---
class PublicKey:
    def __init__(self, key_bytes):
        self.key_bytes = key_bytes
    @staticmethod
    def load_pkcs1(keyfile, format='PEM'):
        return PublicKey(keyfile)
    def save_pkcs1(self, format='PEM'):
        return self.key_bytes

class PrivateKey:
    def __init__(self, key_bytes):
        self.key_bytes = key_bytes
    @staticmethod
    def load_pkcs1(keyfile, format='PEM'):
        return PrivateKey(keyfile)
    def save_pkcs1(self, format='PEM'):
        return self.key_bytes

def newkeys(keysize, *args, **kwargs):
    pub, priv = generate_pqc_kem_keypair()
    return PublicKey(pub), PrivateKey(priv)

def encrypt(message, pub_key):
    """Encrypts message using either Dual-Hybrid or pure ML-KEM. Returns a single packed bytes object."""
    pub_bytes = pub_key.key_bytes if isinstance(pub_key, PublicKey) else pub_key
    res = pqc_encrypt_payload(message, pub_bytes)
    if len(res) == 4:
        return pack_ciphertext(res[0], res[1], res[2], res[3])
    else:
        return pack_ciphertext(res[0], None, res[1], res[2])

def decrypt(crypto, priv_key):
    """Decrypts message from a single packed bytes object."""
    priv_bytes = priv_key.key_bytes if isinstance(priv_key, PrivateKey) else priv_key
    return pqc_decrypt_payload(crypto, priv_bytes)



# --- Emulation interfaces for 'cryptography.hazmat' ---
class CryptographyPrivateKey:
    def __init__(self, priv_bytes):
        self.priv_bytes = priv_bytes
    def public_key(self):
        try:
            priv_dict = json.loads(self.priv_bytes.decode('utf-8'))
            
            # Load RSA private key
            rsa_priv_bytes = base64.b64decode(priv_dict["rsa"])
            rsa_priv = serialization.load_der_private_key(rsa_priv_bytes, password=None)
            
            # Extract RSA public key
            rsa_pub = rsa_priv.public_key()
            rsa_pub_bytes = rsa_pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            pub_dict = {
                "rsa": base64.b64encode(rsa_pub_bytes).decode('ascii'),
                "kem": priv_dict.get("kem_pub", "")
            }
            pub_bytes = json.dumps(pub_dict).encode('utf-8')
        except Exception:
            pub_bytes = self.priv_bytes
        return CryptographyPublicKey(pub_bytes)
    def decrypt(self, ciphertext, padding=None):
        return pqc_decrypt_payload(ciphertext, self.priv_bytes)

class CryptographyPublicKey:
    def __init__(self, pub_bytes):
        self.pub_bytes = pub_bytes
    def encrypt(self, plaintext, padding=None):
        res = pqc_encrypt_payload(plaintext, self.pub_bytes)
        if len(res) == 4:
            return pack_ciphertext(res[0], res[1], res[2], res[3])
        else:
            return pack_ciphertext(res[0], None, res[1], res[2])

def generate_cryptography_private_key(public_exponent, key_size, backend=None):
    pub_bytes, priv_bytes = generate_pqc_kem_keypair()
    return CryptographyPrivateKey(priv_bytes)

def load_der_private_key(data, password=None, backend=None):
    return CryptographyPrivateKey(data)

def load_der_public_key(data, backend=None):
    return CryptographyPublicKey(data)

def load_pem_private_key(data, password=None, backend=None):
    return CryptographyPrivateKey(data)

def load_pem_public_key(data, backend=None):
    return CryptographyPublicKey(data)

# Register submodules dynamically to resolve imports
cryptography_rsa = ModuleType('pqc_helper.cryptography_rsa')
cryptography_rsa.generate_private_key = generate_cryptography_private_key
sys.modules['pqc_helper.cryptography_rsa'] = cryptography_rsa

cryptography_serialization = ModuleType('pqc_helper.cryptography_serialization')
cryptography_serialization.load_der_private_key = load_der_private_key
cryptography_serialization.load_der_public_key = load_der_public_key
cryptography_serialization.load_pem_private_key = load_pem_private_key
cryptography_serialization.load_pem_public_key = load_pem_public_key
sys.modules['pqc_helper.cryptography_serialization'] = cryptography_serialization


# --- Emulation interfaces for 'PyCryptodome' ---
class PyCryptodomeKey:
    def __init__(self, pub_bytes, priv_bytes=None):
        self.pub_bytes = pub_bytes
        self.priv_bytes = priv_bytes
    def publickey(self):
        return PyCryptodomeKey(self.pub_bytes)
    def export_key(self, *args, **kwargs):
        return self.priv_bytes if self.priv_bytes else self.pub_bytes

class PyCryptodomeCipher:
    def __init__(self, key):
        self.key = key
    def encrypt(self, plaintext):
        res = pqc_encrypt_payload(plaintext, self.key.pub_bytes)
        if len(res) == 4:
            return pack_ciphertext(res[0], res[1], res[2], res[3])
        else:
            return pack_ciphertext(res[0], None, res[1], res[2])
    def decrypt(self, ciphertext):
        if not self.key.priv_bytes:
            raise ValueError("Private key required for decryption")
        return pqc_decrypt_payload(ciphertext, self.key.priv_bytes)

def pycryptodome_generate(bits, randfunc=None):
    pub, priv = generate_pqc_kem_keypair()
    return PyCryptodomeKey(pub, priv)

def pycryptodome_import_key(extern_key, passphrase=None):
    return PyCryptodomeKey(extern_key, extern_key)

class PKCS1_OAEP_Mock:
    @staticmethod
    def new(key, *args, **kwargs):
        return PyCryptodomeCipher(key)

pycryptodome_rsa = ModuleType('pqc_helper.pycryptodome_rsa')
pycryptodome_rsa.generate = pycryptodome_generate
pycryptodome_rsa.import_key = pycryptodome_import_key
sys.modules['pqc_helper.pycryptodome_rsa'] = pycryptodome_rsa

pycryptodome_cipher = ModuleType('pqc_helper.pycryptodome_cipher')
pycryptodome_cipher.PKCS1_OAEP = PKCS1_OAEP_Mock
sys.modules['pqc_helper.pycryptodome_cipher'] = pycryptodome_cipher
