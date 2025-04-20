# 🔐 Secure File Transfer System

A secure, GUI-based file transfer and messaging system implemented in Python, designed for confidential communication and file sharing. It leverages **AES** and **RSA** encryption to ensure end-to-end privacy, while allowing users to authenticate, share files, and download them securely with custom decryption passphrases.

## 🚀 Features

- 🔑 **Hybrid Encryption**: Files are encrypted with unique AES keys; AES keys are encrypted using user-defined passphrases via AES and RSA.
- 🧑‍💻 **User Authentication**: Per-session username and password system with custom decryption passphrase input.
- 🖥️ **Cross-Platform GUI**: Built with Tkinter for an intuitive client-server graphical interface.
- 📁 **Drag-and-Drop File Sharing**: Supports sending multiple files without size restriction.
- 🗃️ **Server File Management**: Server displays a list of received files and allows secure downloads with passphrase verification.
- 🔐 **Password-Protected ZIP**: Downloaded files are saved in password-protected ZIP format for additional security.

## 🏗️ Project Structure

- **client.py**: GUI client to send encrypted files/messages 
- **server.py**: GUI server to receive files and handle decryption 
- **keygen.py**: Generates RSA key pair for secure AES key encryption 
- **encryptor.py**: Standalone script to encrypt a file with RSA + AES 
- **decryptor.py**: Standalone script to decrypt files using private RSA key 


## 🧪 How It Works

1. **Client Side**
   - User logs in with username/password and sets a decryption passphrase.
   - The passphrase is used to derive a key via PBKDF2 for encrypting the AES key.
   - The file is encrypted with a random AES key, and that key is encrypted using the derived key.
   - Encrypted file and key metadata are sent to the server.

2. **Server Side**
   - Accepts file uploads and records sender info.
   - Upon download request, asks for the correct passphrase to decrypt the AES key.
   - The decrypted file is saved into a password-protected ZIP.

## Requirements
- Python 3.7+

# Libraries
- pycryptodome
- cryptography
- tkinter

