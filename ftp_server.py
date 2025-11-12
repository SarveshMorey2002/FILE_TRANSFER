import socket
import ssl
import os
import threading

HOST = '127.0.0.1'
PORT = 2121

# Simple user database
USER_DB = {
    'user1': 'pass1',
    'user2': 'pass2'
}

def handle_client(connstream, addr):
    print(f"[+] Connected by {addr}")

    # Authentication
    connstream.send(b'Username: ')
    username = connstream.recv(1024).decode().strip()
    connstream.send(b'Password: ')
    password = connstream.recv(1024).decode().strip()

    if USER_DB.get(username) != password:
        connstream.send(b'Authentication failed. Disconnecting.')
        connstream.close()
        print(f"[-] Authentication failed for {addr}")
        return
    else:
        connstream.send(b'Authentication successful.')

    while True:
        try:
            command = connstream.recv(1024).decode()
            if not command:
                break

            parts = command.split()
            if not parts:
                continue

            cmd = parts[0].upper()
            filename = parts[1] if len(parts) > 1 else None

            if cmd == 'LIST':
                files = os.listdir('.')
                connstream.send('\n'.join(files).encode())

            elif cmd == 'PWD':
                connstream.send(os.getcwd().encode())

            elif cmd == 'CD' and filename:
                try:
                    os.chdir(filename)
                    connstream.send(f'Changed directory to {os.getcwd()}'.encode())
                except Exception as e:
                    connstream.send(f'Error: {str(e)}'.encode())

            elif cmd == 'MKDIR' and filename:
                try:
                    os.mkdir(filename)
                    connstream.send(f'Directory {filename} created.'.encode())
                except Exception as e:
                    connstream.send(f'Error: {str(e)}'.encode())

            elif cmd == 'CREATE' and filename:
                try:
                    with open(filename, 'w') as f:
                        pass
                    connstream.send(f'{filename} created.'.encode())
                except Exception as e:
                    connstream.send(f'Error creating file: {str(e)}'.encode())

            elif cmd == 'READ' and filename:
                if os.path.exists(filename):
                    with open(filename, 'r') as f:
                        connstream.send(f.read().encode())
                else:
                    connstream.send(b'File not found')

            elif cmd == 'UPDATE' and filename:
                if os.path.exists(filename):
                    connstream.send(b'READY')
                    data = connstream.recv(4096).decode()
                    with open(filename, 'w') as f:
                        f.write(data)
                    connstream.send(f'{filename} updated.'.encode())
                else:
                    connstream.send(b'File not found')

            elif cmd == 'DELETE' and filename:
                try:
                    os.remove(filename)
                    connstream.send(f'{filename} deleted.'.encode())
                except Exception as e:
                    connstream.send(f'Error deleting file: {str(e)}'.encode())

            elif cmd == 'GET' and filename:
                if os.path.exists(filename):
                    with open(filename, 'rb') as f:
                        connstream.send(f.read())
                else:
                    connstream.send(b'File not found')

            elif cmd == 'PUT' and filename:
                connstream.send(b'READY')
                data = connstream.recv(4096)
                with open(filename, 'wb') as f:
                    f.write(data)
                connstream.send(f'{filename} uploaded.'.encode())

            elif cmd == 'QUIT':
                connstream.send(b'Goodbye!')
                break

            else:
                connstream.send(b'Unknown or malformed command.')

        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
            break

    connstream.close()
    print(f"[-] Disconnected from {addr}")

# SSL setup
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='server.pem', keyfile='server.key')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print(f"[+] FTP Server listening on {HOST}:{PORT} with SSL")

while True:
    client_socket, addr = server_socket.accept()
    connstream = context.wrap_socket(client_socket, server_side=True)
    threading.Thread(target=handle_client, args=(connstream, addr)).start()