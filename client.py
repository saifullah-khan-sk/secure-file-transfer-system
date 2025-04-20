import os
import socket
import threading
import tkinter as tk
from tkinter import simpledialog, filedialog, scrolledtext, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

SERVER_HOST = 'localhost'
SERVER_PORT = 9998

class SecureClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Client")

        self.username = simpledialog.askstring("Login", "Enter your username:")
        self.password = simpledialog.askstring("Login", "Enter your password:", show='*')
        self.decryption_passphrase = simpledialog.askstring("Key", "Set your decryption key (passphrase):", show='*')

        if not all([self.username, self.password, self.decryption_passphrase]):
            messagebox.showerror("Error", "All fields are required.")
            master.destroy()
            return

        # Derive encryption key from passphrase
        salt = self.username.encode()  # basic static salt from username
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.user_key = kdf.derive(self.decryption_passphrase.encode())

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((SERVER_HOST, SERVER_PORT))

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=60, height=20, state='disabled')
        self.text_area.pack(pady=10)

        self.entry = tk.Entry(master, width=40)
        self.entry.pack(side=tk.LEFT, padx=10)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        self.file_button = tk.Button(master, text="Send File", command=self.send_files)
        self.file_button.pack(side=tk.LEFT, padx=5)

        self.send_auth()
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_auth(self):
        self.socket.send(b"[AUTH]\n" + self.username.encode() + b"\n" + self.password.encode())

    def send_message(self):
        message = self.entry.get()
        if message:
            self.socket.send(message.encode())
            self.log("You: " + message)
            self.entry.delete(0, tk.END)

    def send_files(self):
        file_paths = filedialog.askopenfilenames()
        if not file_paths:
            return

        for path in file_paths:
            self.encrypt_and_send_file(path)

    def encrypt_and_send_file(self, file_path):
        filename = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            data = f.read()

        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Encrypt AES key with user's derived key
        key_cipher = Cipher(algorithms.AES(self.user_key), modes.CFB(iv), backend=default_backend())
        key_encryptor = key_cipher.encryptor()
        encrypted_aes_key = key_encryptor.update(aes_key) + key_encryptor.finalize()

        # Encode binary values to safely transmit in metadata
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key)
        iv_b64 = base64.b64encode(iv)

        meta = b"[FILE_META]\n" + self.username.encode() + b"\n" + filename.encode() + b"\n" + encrypted_key_b64 + b"\n" + iv_b64 + b"\n"
        payload = len(meta).to_bytes(4, 'big') + meta + len(encrypted_data).to_bytes(4, 'big') + encrypted_data
        self.socket.send(payload)
        self.log(f"Sent file: {filename}")

    def receive_messages(self):
        while True:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                self.log("Server: " + data.decode())
            except Exception as e:
                self.log("[Error] " + str(e))
                break

    def log(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')

root = tk.Tk()
app = SecureClient(root)
root.geometry("650x500")
root.mainloop()

