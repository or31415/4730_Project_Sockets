#!/usr/bin/env python3
"""
Simple SSL chat client. Communicates with SSL chat server using encrypted TCP over TLS
Commands:
  /pm <username> <message>   - send private message
  /list                      - ask server for user list
  /quit                      - disconnect
All other input is shown to everyone.
"""
import socket
import ssl
import threading
import argparse
import sys

def receive_loop(ssl_sock):
    try:
        fileobj = ssl_sock.makefile('r')
        while True:
            line = fileobj.readline()
            if not line:
                print("Connection closed by server.")
                break
            print(line.rstrip('\n'))
    except Exception as e:
        print("Receive error:", e)
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass
        # exit the program if loop ends
        print("Exiting receive thread.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="SSL Chat Client")
    parser.add_argument('--host', required=True, help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=12345)
    parser.add_argument('--cafile', default='cert.pem', help='CA file to verify server certificate (use server cert for self-signed)')
    parser.add_argument('--username', required=True, help='Your username')
    args = parser.parse_args()

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.cafile)
    # For self-signed cert, require verification against cafile (the server cert)
    # ALWAYS REQUIRE VERIFICATION FOR ACTUAL USE!!
    # skip verification (for debugging only), uncomment:
    # context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE

    # create tcp socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_sock.connect((args.host, args.port))
        # wrap tcp socket in ssl context to encrypt traffic and verify server's certificate
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=args.host)
    except Exception as e:
        print("Failed to connect or establish SSL:", e)
        return

    # receive initial prompt and then send username
    try:
        # start receiver thread
        t = threading.Thread(target=receive_loop, args=(ssl_sock,), daemon=True)
        t.start()

        # Wait to get server prompt (not strictly necessary)
        # send username (must be line-terminated)
        ssl_sock.sendall((args.username + "\n").encode())

        # input loop to read user input and send to server
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line:
                continue
            ssl_sock.sendall((line + "\n").encode())

            # exit cleanly
            if line.strip() == '/quit':
                break
    except KeyboardInterrupt:
        print("\nInterrupted, disconnecting...")
    finally:
        try:
            ssl_sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            ssl_sock.close()
        except Exception:
            pass
        print("Client exiting.")

if __name__ == '__main__':
    main()
