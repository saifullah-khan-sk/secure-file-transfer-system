from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Load file
with open("input.txt", "rb") as f:
    data = f.read()

# Generate AES key
aes_key = get_random_bytes(16)
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

# Save encrypted file
with open("files/encrypted_file.bin", "wb") as f:
    [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

# Load public key and encrypt AES key
recipient_key = RSA.import_key(open("keys/public_key.pem").read())
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Save encrypted AES key
with open("files/encrypted_key.bin", "wb") as f:
    f.write(enc_aes_key)
