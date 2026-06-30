import rsa

# Generate a new 2048-bit RSA keypair
(pubkey, privkey) = rsa.newkeys(2048)

message = "Hello, this is a secret classical message."

# Encrypt the message using the public key
encrypted_msg = rsa.encrypt(message.encode('utf-8'), pubkey)
print("Encrypted payload:", encrypted_msg)

# Decrypt the message using the private key
decrypted_msg = rsa.decrypt(encrypted_msg, privkey)
print("Decrypted payload:", decrypted_msg.decode('utf-8'))
