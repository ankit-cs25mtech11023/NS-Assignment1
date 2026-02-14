import socket
import threading
import os
import datetime
import hashlib
import secrets # For secure random nonce

# Configuration
HOST = '0.0.0.0'
PORT = 8080
BUFFER_SIZE = 4096
CREDENTIALS_FILE = "credentials.txt"
LOG_FILE = "server.log"

# Global Variables

blocked_users = {} 
login_attempts = {}

# Lock for thread-safe logging and variable access
print_lock = threading.Lock()
auth_lock = threading.Lock()

def log_event(command, response):
    """Logs requests and responses to server.log with timestamp."""
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with print_lock:
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} REQUEST: {command}\n")
            f.write(f"{timestamp} RESPONSE: {response}\n")

def load_credentials():
    creds = {}
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            for line in f:
                if ':' in line:
                    user, secret = line.strip().split(':', 1)
                    creds[user] = secret
    return creds

def handle_client(client_socket, addr):
    
    #Handle a single client connection in a separate thread.
    print(f"[NEW CONNECTION] {addr} connected.")
    
    session_key = None
    username = None
    
    try: 
        # 1. Receive Username
        username = client_socket.recv(BUFFER_SIZE).decode().strip()
        
        # Check Lockout Policy 
        with auth_lock:
            if username in blocked_users:
                client_socket.sendall("AUTH_FAIL: Account Blocked".encode())
                client_socket.close()
                return

        creds = load_credentials()
        if username not in creds:
            # Fake auth to prevent username enumeration
            client_socket.sendall("AUTH_FAIL: Invalid User".encode())
            client_socket.close()
            return

        shared_secret = creds[username]

        # 2. Server generates and sends random nonce
        nonce = str(secrets.randbits(64))
        client_socket.sendall(nonce.encode())

        # 3. Receive Hash from Client
        client_hash = client_socket.recv(BUFFER_SIZE).decode().strip()

        # 4. Verify Hash: HASH(nonce || shared_secret)
        expected_str = nonce + shared_secret
        expected_hash = hashlib.sha256(expected_str.encode()).hexdigest()

        if client_hash == expected_hash:
            client_socket.sendall("AUTH_SUCCESS".encode())
            # Reset attempts on success
            with auth_lock:
                if username in login_attempts:
                    del login_attempts[username]
        else:
            msg = ""
            # Handle Failed Attempt
            with auth_lock:
                login_attempts[username] = login_attempts.get(username, 0) + 1
                attempts = login_attempts[username]
                if attempts >= 3:
                    blocked_users[username] = True
                    msg = "AUTH_FAIL: Account Blocked"
                else:
                    msg = "AUTH_FAIL: Incorrect Credentials"
            client_socket.sendall(msg.encode())
            client_socket.close()
            return

        # Receive Client's P, G, and Public Key A
        dh_data = client_socket.recv(BUFFER_SIZE).decode().strip()
        P_str, G_str, A_str = dh_data.split(',')
        P = int(P_str)
        G = int(G_str)
        A = int(A_str)

        # Server generates private key b
        b = secrets.randbelow(P - 1) + 1
        # Server computes Public Key B = (G^b) % P
        B = pow(G, b, P)

        # Server computes Session Key = (A^b) % P
        session_int = pow(A, b, P)
        session_key = str(session_int) # Store as string for now
        
        # Send Server's Public Key B to client
        client_socket.sendall(str(B).encode())
        
        print(f"[SECURE] Session Key established for {username}.")

        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            
            command_line = data.decode('utf-8').strip()
            parts = command_line.split()
            if not parts: continue
            
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            response = ""

            if cmd == "LIST":
                # Re-using logic from Task 1
                try:
                    files = [f for f in os.listdir('.') if os.path.isfile(f)]
                    response = " ".join(files) if files else "Empty Directory"
                except: response = "ERROR"
            
            elif cmd == "INFO" and arg:
                 if os.path.exists(arg):
                    st = os.stat(arg)
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    ctime = datetime.datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    response = f"Size: {st.st_size} bytes, Perms: {oct(st.st_mode)[-3:]}, Modified: {mtime}, Created: {ctime}"
                 else: response = "ERROR: File not found"

            elif cmd == "GETSIZE" and arg:
                if os.path.exists(arg): response = f"{os.path.getsize(arg)} bytes"
                else: response = "ERROR: File not found"

            elif cmd == "QUIT":
                log_event(command_line, "Connection Terminated")
                break
            else:
                response = "ERROR: Invalid Command"

            log_event(command_line, response)
            client_socket.sendall(response.encode('utf-8'))

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[STARTING] Server listening on {PORT}")

    while True:
        conn, addr = server.accept()
        # Create a new thread for each client 
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()