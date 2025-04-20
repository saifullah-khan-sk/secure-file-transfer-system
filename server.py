import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, Listbox, Button, Label
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import zipfile
import secrets

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9998
BUFFER_SIZE = 4096
SAVE_DIR = "received_files"

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

clients = {}
file_records = []  # stores (username, filename, encrypted_data, encrypted_key_b64, iv_b64)

class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure Server")

        self.label = Label(master, text="Received Files")
        self.label.pack()

        self.listbox = Listbox(master, width=60)
        self.listbox.pack(pady=10)

        self.download_button = Button(master, text="Download Selected File", command=self.download_selected)
        self.download_button.pack(pady=5)

        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((SERVER_HOST, SERVER_PORT))
        server.listen(5)
        print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()

    def handle_client(self, client_sock):
        try:
            auth_header = client_sock.recv(1024)
            if b"[AUTH]" in auth_header:
                lines = auth_header.split(b"\n")
                username = lines[1].decode()
                password = lines[2].decode()  # Not used in this example

            while True:
                size_meta = client_sock.recv(4)
                if not size_meta:
                    break
                meta_len = int.from_bytes(size_meta, 'big')
                meta = client_sock.recv(meta_len)

                size_data = client_sock.recv(4)
                data_len = int.from_bytes(size_data, 'big')
                encrypted_data = b""
                while len(encrypted_data) < data_len:
                    encrypted_data += client_sock.recv(min(BUFFER_SIZE, data_len - len(encrypted_data)))

                parts = meta.split(b"\n")
                if parts[0] == b"[FILE_META]":
                    sender = parts[1].decode()
                    filename = parts[2].decode()
                    encrypted_key_b64 = parts[3]
                    iv_b64 = parts[4]

                    record = (sender, filename, encrypted_data, encrypted_key_b64, iv_b64)
                    file_records.append(record)
                    self.listbox.insert(tk.END, f"{sender} - {filename}")

        except Exception as e:
            print(f"Error: {e}")

    def download_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Please select a file.")
            return

        index = sel[0]
        sender, filename, encrypted_data, encrypted_key_b64, iv_b64 = file_records[index]

        passphrase = simpledialog.askstring("Key Required", f"Enter decryption key set by {sender}:", show='*')
        if not passphrase:
            return

        try:
            salt = sender.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            user_key = kdf.derive(passphrase.encode())

            encrypted_key = base64.b64decode(encrypted_key_b64)
            iv = base64.b64decode(iv_b64)

            key_cipher = Cipher(algorithms.AES(user_key), modes.CFB(iv), backend=default_backend())
            key_decryptor = key_cipher.decryptor()
            aes_key = key_decryptor.update(encrypted_key) + key_decryptor.finalize()

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            save_path = filedialog.asksaveasfilename(defaultextension=".zip", initialfile=filename+".zip")
            if not save_path:
                return

            zip_password = secrets.token_urlsafe(12)[:10]  # Simple password for demo
            with zipfile.ZipFile(save_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                file_inside_zip = os.path.basename(filename)
                with open(file_inside_zip, 'wb') as f:
                    f.write(decrypted_data)
                zipf.write(file_inside_zip)
                os.remove(file_inside_zip)

            messagebox.showinfo("Success", f"Decrypted file saved as ZIP.\n(Password: {zip_password})")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file:\n{e}")

root = tk.Tk()
app = ServerGUI(root)
root.geometry("600x400")
root.mainloop()

