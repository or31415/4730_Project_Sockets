#!/usr/bin/env python3
"""
Multi-client chat server with SSL and per-client threads. Each client runs in its own thread.
Clients connect with SSL/TLS
Private message command: /pm <username> <message>
Other commands from client:
  /list  - get list of connected users
  /quit  - disconnect
"""
import socket
import ssl
import threading
import argparse
import sys

HOST = '0.0.0.0'
PORT = 12345

clients_lock = threading.Lock()
# username -> (ssl_socket, address)
clients = {}

# broadcasts messages to all clients (group chat part)
def broadcast(sender_username, message):
    """Send message to all connected clients except the sender."""
    with clients_lock:
        for username, (conn, addr) in clients.items():
            if username == sender_username:
                continue
            try:
                conn.sendall((f"[{sender_username}] {message}\n").encode())
            except Exception:
                # ignore send errors client thread will handle disconnection
                pass

def send_private(sender_username, recipient, message):
    with clients_lock:
        if recipient in clients:
            conn, _ = clients[recipient]
            try:
                conn.sendall((f"[PM from {sender_username}] {message}\n").encode())
                return True
            except Exception:
                return False
        else:
            return False

def handle_client(conn, addr):
    """
    Each client must first send their username (one line).
    Then server listens for commands or messages.
    """
    try:
        conn.sendall(b"Welcome! Please type your username and press Enter:\n")
        # get username
        fileobj = conn.makefile('r')  # text-mode file for line reading
        username = fileobj.readline().strip()
        if not username:
            conn.close()
            return

        # check for unique username
        with clients_lock:
            if username in clients:
                conn.sendall(b"Username already in use. Disconnecting.\n")
                conn.close()
                return
            clients[username] = (conn, addr)

        conn.sendall((f"Hello {username}! You can send messages; use /pm <user> <msg> for private.\n").encode())
        broadcast("Server", f"{username} has joined the chat.")

        # read loop
        while True:
            line = fileobj.readline()
            if not line:
                break  # client closed connection
            line = line.rstrip('\n')
            if not line:
                continue

            if line.startswith('/pm '):
                parts = line.split(' ', 2)
                if len(parts) < 3:
                    conn.sendall(b"Usage: /pm <username> <message>\n")
                    continue
                recipient, msg = parts[1], parts[2]
                ok = send_private(username, recipient, msg)
                if ok:
                    conn.sendall((f"[PM to {recipient}] {msg}\n").encode())
                else:
                    conn.sendall((f"User {recipient} not found or message failed.\n").encode())

            elif line == '/list':
                with clients_lock:
                    names = ", ".join(clients.keys())
                conn.sendall((f"Connected users: {names}\n").encode())

            elif line == '/quit':
                conn.sendall(b"Goodbye!\n")
                break

            else:
                # broadcast to all
                broadcast(username, line)

    except Exception as e:
        # catch high-level exceptions to ensure cleanup
        print(f"Exception for client {addr}: {e}")
    finally:
        # cleanup
        removed = None
        with clients_lock:
            for name, (c, a) in list(clients.items()):
                if c is conn:
                    removed = name
                    del clients[name]
                    break
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        if removed:
            print(f"{removed} disconnected.")
            broadcast("Server", f"{removed} has left the chat.")

def main():
    parser = argparse.ArgumentParser(description="SSL Chat Server")
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--cert', default='cert.pem', help='Server certificate file (PEM)')
    parser.add_argument('--key', default='key.pem', help='Server private key file (PEM)')
    args = parser.parse_args()

    # wrap socket with ssl for encryption
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)

    # create the tcp socket
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind((args.host, args.port))
    bindsock.listen(100)
    print(f"Server listening on {args.host}:{args.port} (SSL)")

    try:
        while True:
            newsock, addr = bindsock.accept()
            try:
                sslconn = context.wrap_socket(newsock, server_side=True)
            except ssl.SSLError as e:
                print(f"SSL error during handshake from {addr}: {e}")
                newsock.close()
                continue
            # threads to handle multiple clients
            t = threading.Thread(target=handle_client, args=(sslconn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")

    # safely close server even if stopped manually    
    finally:
        with clients_lock:
            for name, (c, a) in clients.items():
                try:
                    c.sendall(b"Server is shutting down.\n")
                except Exception:
                    pass
                try:
                    c.shutdown(socket.SHUT_RDWR)
                    c.close()
                except Exception:
                    pass
        bindsock.close()

if __name__ == '__main__':
    main()
