import socket
import ssl
import os
import threading
import logging
import re

HOST = '127.0.0.1'
PORT = 2121

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ftp_root")
os.makedirs(BASE_DIR, exist_ok=True)

# Plain text user database 
USER_DB = {
    'user1': 'pass1',
    'user2': 'pass2',
    'user3': 'pass3',
    'user4': 'pass4',
    'user5': 'pass5'
}

# Configure logging
logging.basicConfig(filename='ftp_server.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def validate_filename(filename):
    """Allow only alphanumeric, underscore, dash, and dot."""
    if not filename or not re.match(r'^[\w\-.]+$', filename):
        raise ValueError("Invalid filename")
    return filename

def safe_path(current_dir, filename):
    filepath = os.path.normpath(os.path.join(current_dir, filename))
    if not filepath.startswith(BASE_DIR):
        raise Exception("Access denied: Invalid path")
    return filepath

def send_response(conn, message):
    conn.sendall((message + "\n").encode())

def recv_command(conn):
    data = conn.recv(4096).decode().strip()
    return data

def handle_client(connstream, addr):
    logging.info(f"Connected by {addr}")
    send_response(connstream, "Username:")
    username = recv_command(connstream)
    send_response(connstream, "Password:")
    password = recv_command(connstream)

    if USER_DB.get(username) != password:
        send_response(connstream, "Authentication failed. Disconnecting.")
        logging.warning(f"Authentication failed for {addr} (username: {username})")
        connstream.close()
        return
    else:
        send_response(connstream, "Authentication successful.")
        logging.info(f"User '{username}' authenticated successfully.")

    # Create user-specific directory
    user_dir = os.path.join(BASE_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    current_dir = user_dir

    while True:
        try:
            command = recv_command(connstream)
            if not command:
                break

            parts = command.split()
            cmd = parts[0].upper()
            filename = parts[1] if len(parts) > 1 else None

            if cmd == 'LIST':
                files = os.listdir(current_dir)
                send_response(connstream, "\n".join(files))
                logging.info(f"{username} listed files in {current_dir}")

            elif cmd == 'PWD':
                send_response(connstream, current_dir)
                logging.info(f"{username} checked current directory")

            elif cmd == 'CD' and filename:
                try:
                    validate_filename(filename)
                    new_dir = safe_path(current_dir, filename)
                    if os.path.isdir(new_dir):
                        current_dir = new_dir
                        send_response(connstream, f'Changed directory to {current_dir}')
                        logging.info(f"{username} changed directory to {current_dir}")
                    else:
                        send_response(connstream, 'Error: Directory not found')
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to change directory: {e}")

            elif cmd == 'MKDIR' and filename:
                try:
                    validate_filename(filename)
                    os.mkdir(safe_path(current_dir, filename))
                    send_response(connstream, f'Directory {filename} created.')
                    logging.info(f"{username} created directory {filename}")
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to create directory: {e}")

            elif cmd == 'CREATE' and filename:
                try:
                    validate_filename(filename)
                    with open(safe_path(current_dir, filename), 'w') as f:
                        pass
                    send_response(connstream, f'{filename} created.')
                    logging.info(f"{username} created file {filename}")
                except Exception as e:
                    send_response(connstream, f'Error creating file: {str(e)}')
                    logging.error(f"{username} failed to create file: {e}")

            elif cmd == 'READ' and filename:
                try:
                    validate_filename(filename)
                    filepath = safe_path(current_dir, filename)
                    if os.path.exists(filepath):
                        with open(filepath, 'r') as f:
                            send_response(connstream, f.read())
                        logging.info(f"{username} read file {filename}")
                    else:
                        send_response(connstream, 'File not found')
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to read file: {e}")

            elif cmd == 'UPDATE' and filename:
                try:
                    validate_filename(filename)
                    filepath = safe_path(current_dir, filename)
                    if os.path.exists(filepath):
                        send_response(connstream, 'READY')
                        data = recv_command(connstream)
                        with open(filepath, 'w') as f:
                            f.write(data)
                        send_response(connstream, f'{filename} updated.')
                        logging.info(f"{username} updated file {filename}")
                    else:
                        send_response(connstream, 'File not found')
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to update file: {e}")

            elif cmd == 'DELETE' and filename:
                try:
                    validate_filename(filename)
                    os.remove(safe_path(current_dir, filename))
                    send_response(connstream, f'{filename} deleted.')
                    logging.info(f"{username} deleted file {filename}")
                except Exception as e:
                    send_response(connstream, f'Error deleting file: {str(e)}')
                    logging.error(f"{username} failed to delete file: {e}")

            elif cmd == 'GET' and filename:
                try:
                    validate_filename(filename)
                    filepath = safe_path(current_dir, filename)
                    if os.path.exists(filepath):
                        send_response(connstream, 'READY')
                        with open(filepath, 'rb') as f:
                            while chunk := f.read(4096):
                                connstream.sendall(chunk)
                        connstream.sendall(b'DONE')
                        logging.info(f"{username} downloaded file {filename}")
                    else:
                        send_response(connstream, 'File not found')
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to download file: {e}")

            elif cmd == 'PUT' and filename:
                try:
                    validate_filename(filename)
                    send_response(connstream, 'READY')
                    filepath = safe_path(current_dir, filename)
                    with open(filepath, 'wb') as f:
                        while True:
                            chunk = connstream.recv(4096)
                            if b'DONE' in chunk:
                                f.write(chunk.replace(b'DONE', b''))
                                break
                            f.write(chunk)
                    send_response(connstream, f'{filename} uploaded.')
                    logging.info(f"{username} uploaded file {filename}")
                except Exception as e:
                    send_response(connstream, f'Error: {str(e)}')
                    logging.error(f"{username} failed to upload file: {e}")

            elif cmd == 'QUIT':
                send_response(connstream, 'Goodbye!')
                logging.info(f"{username} disconnected")
                break

            else:
                send_response(connstream, 'Unknown or malformed command.')
                logging.warning(f"{username} sent unknown command: {command}")

        except Exception as e:
            logging.error(f"Error with {addr}: {e}")
            break

    connstream.close()
    logging.info(f"Disconnected from {addr}")

# SSL setup with certificate verification
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='server.pem', keyfile='server.key')
context.minimum_version = ssl.TLSVersion.TLSv1_2

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print(f"[+] FTP Server listening on {HOST}:{PORT} with SSL")

while True:
    client_socket, addr = server_socket.accept()
    connstream = context.wrap_socket(client_socket, server_side=True)
    threading.Thread(target=handle_client, args=(connstream, addr)).start()