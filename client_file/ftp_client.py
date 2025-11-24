import socket
import ssl
import os

HOST = 'localhost'  
PORT = 2121

context = ssl.create_default_context()
context.verify_mode = ssl.CERT_REQUIRED

cert_path = os.path.join(os.path.dirname(__file__), 'server.pem')

# Fallback logic if certificate is missing
try:
    context.load_verify_locations(cert_path)
    context.check_hostname = True
except FileNotFoundError:
    print("Warning: Certificate not found. Disabling verification for testing.")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = context.wrap_socket(client_socket, server_hostname=HOST)
ssl_socket.connect((HOST, PORT))

def recv_response():
    return ssl_socket.recv(4096).decode().strip()

print(recv_response(), end=' ')
username = input()
ssl_socket.sendall((username + "\n").encode())

print(recv_response(), end=' ')
password = input()
ssl_socket.sendall((password + "\n").encode())

auth_response = recv_response()
print(auth_response)
if "failed" in auth_response.lower():
    ssl_socket.close()
    exit()

while True:
    command = input("Enter command: ").strip()
    if not command:
        continue

    parts = command.split()
    cmd = parts[0].upper()
    ssl_socket.sendall((command + "\n").encode())

    if cmd == 'GET' and len(parts) > 1:
        filename = parts[1]
        response = recv_response()
        if response == 'READY':
            with open(f'downloaded_{filename}', 'wb') as f:
                while True:
                    chunk = ssl_socket.recv(4096)
                    if b'DONE' in chunk:
                        f.write(chunk.replace(b'DONE', b''))
                        break
                    f.write(chunk)
            print(f"{filename} downloaded.")
        else:
            print(response)

    elif cmd == 'PUT' and len(parts) > 1:
        filename = parts[1]
        if os.path.exists(filename):
            response = recv_response()
            if response == 'READY':
                with open(filename, 'rb') as f:
                    while chunk := f.read(4096):
                        ssl_socket.sendall(chunk)
                ssl_socket.sendall(b'DONE')
                print(recv_response())
        else:
            print("File not found on client side.")

    elif cmd == 'UPDATE' and len(parts) > 1:
        filename = parts[1]
        response = recv_response()
        if response == 'READY':
            new_content = input("Enter new content: ")
            ssl_socket.sendall((new_content + "\n").encode())
            print(recv_response())
        else:
            print(response)

    elif cmd == 'QUIT':
        print(recv_response())
        break

    else:
        print(recv_response())

ssl_socket.close()