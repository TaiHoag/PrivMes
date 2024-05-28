import socket
import ssl
import threading
import sqlite3
import schedule
import time
import os
import zipfile
from cryptography.fernet import Fernet
import base64

# Database setup
def setup_database():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, message TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

setup_database()

# Backup function
def backup_database():
    zip_filename = time.strftime("%Y%m%d%H%M%S") + ".zip"
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        zipf.write('messages.db')
    # Manage backup files
    backups = sorted([f for f in os.listdir() if f.endswith('.zip')])
    if len(backups) > 100:
        os.remove(backups[0])

schedule.every().day.at("00:00").do(backup_database)

# SSL context setup
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.pem", keyfile="server.key")

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12345))
server_socket.listen(5)
print("Server started on port 12345")

clients = {}

def broadcast(message, sender):
    for client in list(clients.keys()):  # Use a list to avoid runtime dictionary changes
        if client != sender:
            try:
                client.send(message)
            except Exception as e:
                print(f"Broadcast error: {e}")
                client.close()
                if client in clients:
                    del clients[client]

def save_message_to_db(sender, receiver, message):
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)", 
              (sender, receiver, message, time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def handle_client(client_socket, addr):
    print(f"Connection from {addr}")
    clients[client_socket] = addr
    try:
        while True:
            message = client_socket.recv(1024)
            if message:
                sender, receiver, encrypted_message = message.decode().split(':', 2)
                save_message_to_db(sender, receiver, encrypted_message)
                broadcast(message, client_socket)
    except OSError as e:
        print(f"Client socket error: {e}")
    finally:
        print(f"Closing connection from {addr}")
        client_socket.close()
        if client_socket in clients:
            del clients[client_socket]

def accept_connections():
    while True:
        client_socket, addr = server_socket.accept()
        ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
        client_handler = threading.Thread(target=handle_client, args=(ssl_client_socket, addr))
        client_handler.start()

accept_thread = threading.Thread(target=accept_connections)
accept_thread.start()

# Run scheduled tasks
while True:
    schedule.run_pending()
    time.sleep(1)
