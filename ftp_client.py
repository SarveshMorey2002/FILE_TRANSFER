import socket
import ssl

HOST = '127.0.0.1'
PORT = 2121

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # For testing only

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = context.wrap_socket(client_socket, server_hostname=HOST)
ssl_socket.connect((HOST, PORT))

# Authentication
print(ssl_socket.recv(1024).decode(), end='')
username = input()
ssl_socket.send(username.encode())

print(ssl_socket.recv(1024).decode(), end='')
password = input()
ssl_socket.send(password.encode())

auth_response = ssl_socket.recv(1024).decode()
print(auth_response)
if "failed" in auth_response.lower():
    ssl_socket.close()
    exit()

while True:
    command = input("Enter command: ")
    ssl_socket.send(command.encode())

    parts = command.split()
    if not parts:
        continue

    cmd = parts[0].upper()
    filename = parts[1] if len(parts) > 1 else None

    if cmd == 'GET' and filename:
        data = ssl_socket.recv(4096)
        with open(f'downloaded_{filename}', 'wb') as f:
            f.write(data)
        print(f"{filename} downloaded.")

    elif cmd == 'PUT' and filename:
        try:
            with open(filename, 'rb') as f:
                ready = ssl_socket.recv(1024).decode()
                if ready == 'READY':
                    ssl_socket.send(f.read())
                    response = ssl_socket.recv(1024).decode()
                    print(response)
        except FileNotFoundError:
            print("File not found on client side.")

    elif cmd == 'UPDATE' and filename:
        try:
            with open(filename, 'r') as f:
                new_content = f.read()
                ready = ssl_socket.recv(1024).decode()
                if ready == 'READY':
                    ssl_socket.send(new_content.encode())
                    response = ssl_socket.recv(1024).decode()
                    print(response)
        except FileNotFoundError:
            print("File not found on client side.")

    elif cmd == 'READ':
        response = ssl_socket.recv(4096).decode()
        print(f"File contents:\n{response}")

    elif cmd in ['CREATE', 'DELETE', 'LIST', 'PWD', 'CD', 'MKDIR']:
        response = ssl_socket.recv(1024).decode()
        print(response)

    elif cmd == 'QUIT':
        print(ssl_socket.recv(1024).decode())
        break

    else:
        response = ssl_socket.recv(1024).decode()
        print(response)

ssl_socket.close()