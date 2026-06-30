import pqc_helper

# Generate a new 2048-bit RSA keypair
(pubkey, privkey) = pqc_helper.generate_pqc_kem_keypair(2048)

message = "Hello, this is a secret classical message."

# Encrypt the message using the public key
encrypted_msg = pqc_helper.pqc_encrypt_payload(message.encode('utf-8'), pubkey)
print("Encrypted payload:", encrypted_msg)

# Decrypt the message using the private key
decrypted_msg = pqc_helper.pqc_decrypt_payload(*encrypted_msg, privkey)
print("Decrypted payload:", decrypted_msg.decode('utf-8'))
