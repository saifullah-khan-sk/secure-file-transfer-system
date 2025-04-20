from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# Load encrypted AES key
private_key = RSA.import_key(open("private_key.pem").read())
enc_aes_key = open("encrypted_key.bin", "rb").read()
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(enc_aes_key)

# Load encrypted file
with open("encrypted_file.bin", "rb") as f:
    nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

# Decrypt file
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Save decrypted file
with open("decrypted_file.txt", "wb") as f:
    f.write(data)
