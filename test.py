import base64

def decrypt_password(enc_password, key):
    # Decode the base64 encoded password
    enc_password_bytes = base64.b64decode(enc_password)

    # Convert the key to bytes
    key_bytes = key.encode('ascii')

    # Decrypt the password
    decrypted_bytes = bytearray(len(enc_password_bytes))
    for i in range(len(enc_password_bytes)):
        decrypted_bytes[i] = enc_password_bytes[i] ^ key_bytes[i % len(key_bytes)] ^ 223

    # Convert the decrypted bytes to string
    decrypted_password = decrypted_bytes.decode('ascii')

    return decrypted_password

# Encrypted password and key
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

# Decrypt the password
decrypted_password = decrypt_password(enc_password, key)
print(f"Decrypted Password: {decrypted_password}")
