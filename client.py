import socket
import ssl
import threading
import customtkinter as ctk
from tkinter import simpledialog
from cryptography.fernet import Fernet
import base64

def load_vocab():
    with open('vocab.txt', 'r', encoding='utf-8') as f:
        vocab = f.read().splitlines()
    return vocab

vocab = load_vocab()

# Generate or load the encryption key
def generate_key(passcode):
    return base64.urlsafe_b64encode(passcode.encode().ljust(32))

class Client:
    def __init__(self, master):
        self.master = master
        self.master.title("Messaging App")

        self.frame = ctk.CTkFrame(master)
        self.frame.pack(pady=20, padx=60, fill="both", expand=True)

        self.label = ctk.CTkLabel(self.frame, text="Enter your name:")
        self.label.pack(pady=12, padx=10)

        self.name_entry = ctk.CTkEntry(self.frame, width=200)
        self.name_entry.pack(pady=12, padx=10)

        self.name_button = ctk.CTkButton(self.frame, text="Submit", command=self.set_name)
        self.name_button.pack(pady=12, padx=10)

        self.text_display = ctk.CTkTextbox(self.frame, state='disabled', width=400, height=300)
        self.text_display.pack(pady=12, padx=10)

        self.entry = ctk.CTkEntry(self.frame, width=300)
        self.entry.pack(pady=12, padx=10)
        self.entry.bind("<Return>", self.send_message)

        self.passcode = simpledialog.askstring("Passcode", "Enter a 6-digit passcode:", show='*')

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False  # Disable hostname verification for development
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification for development
        context.load_verify_locations('server.pem')
        self.ssl_client_socket = context.wrap_socket(self.client_socket, server_hostname='localhost')
        try:
            self.ssl_client_socket.connect(('127.0.0.1', 12345))
            receive_thread = threading.Thread(target=self.receive_message)
            receive_thread.start()
        except Exception as e:
            print(f"Connection error: {e}")
            self.master.quit()

    def set_name(self):
        self.name = self.name_entry.get()
        self.name_entry.pack_forget()
        self.name_button.pack_forget()
        self.label.configure(text=f"Welcome, {self.name}")

    def send_message(self, event):
        if not hasattr(self, 'name'):
            return

        message = self.entry.get()
        self.entry.delete(0, ctk.END)
        encrypted_message = self.encrypt_message(message)
        try:
            self.ssl_client_socket.send(f"{self.name}:{self.name}:{encrypted_message}".encode())
            self.display_message(f"You: {message}")
        except OSError as e:
            print(f"Send message error: {e}")
            self.ssl_client_socket.close()
            self.master.quit()

    def receive_message(self):
        while True:
            try:
                message = self.ssl_client_socket.recv(1024).decode()
                if not message:
                    break
                sender, receiver, encrypted_message = message.split(':', 2)
                decrypted_message = self.decrypt_message(encrypted_message)
                self.display_message(f"{sender}: {decrypted_message}")
            except OSError as e:
                print(f"Receive message error: {e}")
                self.ssl_client_socket.close()
                break

    def encrypt_message(self, message):
        f = Fernet(generate_key(self.passcode))
        encrypted_message = f.encrypt(message.encode())
        base64_message = base64.urlsafe_b64encode(encrypted_message).decode()
        return ''.join([vocab[ord(char) % len(vocab)] for char in base64_message])

    def decrypt_message(self, message):
        base64_message = ''.join([chr(vocab.index(char)) for char in message])
        encrypted_message = base64.urlsafe_b64decode(base64_message.encode())
        f = Fernet(generate_key(self.passcode))
        return f.decrypt(encrypted_message).decode()

    def display_message(self, message):
        self.text_display.configure(state='normal')
        self.text_display.insert("end", message + '\n')
        self.text_display.configure(state='disabled')

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    client = Client(root)
    root.mainloop()
