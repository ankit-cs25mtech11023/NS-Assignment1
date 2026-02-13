import socket
import threading
import os
import datetime
import hashlib
import secrets

# Configuration
HOST = '0.0.0.0'
PORT = 8080
BUFFER_SIZE = 4096
CREDENTIALS_FILE = "credentials.txt"
LOG_FILE = "server.log"
CHUNK_SIZE = 1024  # [cite: 82]

# Global Locks & Storage
blocked_users = {} 
login_attempts = {}
print_lock = threading.Lock()
auth_lock = threading.Lock()

def log_event(command, response):
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

def calculate_mac(data, seq_no, session_key):
    """
    Computes MAC = HASH(DATA || SEQ_NO || SESSION_KEY) [cite: 87]
    """
    # Convert seq_no and key to bytes for concatenation
    seq_bytes = str(seq_no).encode('utf-8')
    key_bytes = str(session_key).encode('utf-8')
    
    # payload = DATA + SEQ_NO + SESSION_KEY
    payload = data + seq_bytes + key_bytes
    return hashlib.sha256(payload).hexdigest()

def handle_get_command(client_socket, filename, session_key):
    """
    Handles the file download process (Server sends to Client).
    """
    if not os.path.exists(filename):
        client_socket.sendall("FILE NOT AVAILABLE".encode()) # [cite: 79]
        return "FILE NOT AVAILABLE"

    # 1. Send File Existence confirmation
    file_size = os.path.getsize(filename)
    client_socket.sendall(f"FILE_FOUND {file_size}".encode())
    
    # Wait briefly for client to be ready (optional but good for stability)
    # In a production app we'd wait for an ACK, but here we stream.
    
    seq_no = 0
    with open(filename, 'rb') as f:
        while True:
            # 2. Read Chunk [cite: 82]
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # 3. Calculate MAC [cite: 87]
            mac = calculate_mac(chunk, seq_no, session_key)
            
            # 4. Construct Packet
            # format: SEQ_NO(4 bytes) + DATA_LEN(4 bytes) + DATA + MAC(64 bytes)
            # We need a robust binary format to handle variable data size
            
            # Protocol Header: 8 bytes total (4 for SEQ, 4 for LEN)
            header = seq_no.to_bytes(4, byteorder='big') + len(chunk).to_bytes(4, byteorder='big')
            mac_bytes = mac.encode('utf-8') # 64 bytes fixed
            
            packet = header + chunk + mac_bytes
            
            # 5. Send Packet
            client_socket.sendall(packet)
            seq_no += 1
            
    # Send End of Transmission indicator
    # We send a special packet with 0 length data to indicate done
    end_header = seq_no.to_bytes(4, byteorder='big') + (0).to_bytes(4, byteorder='big')
    # Dummy MAC for the EOF packet (client will likely ignore, but consistent format helps)
    dummy_mac = calculate_mac(b"", seq_no, session_key).encode('utf-8')
    client_socket.sendall(end_header + dummy_mac)
    
    return f"File {filename} sent ({file_size} bytes)"

def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    session_key = None
    username = None
    
    try:
        # --- PHASE 1: AUTH ---
        username = client_socket.recv(BUFFER_SIZE).decode().strip()
        
        with auth_lock:
            if username in blocked_users:
                client_socket.sendall("AUTH_FAIL: Account Blocked".encode())
                client_socket.close()
                return

        creds = load_credentials()
        if username not in creds:
            client_socket.sendall("AUTH_FAIL: Invalid User".encode())
            client_socket.close()
            return

        shared_secret = creds[username]
        nonce = str(secrets.randbits(64))
        client_socket.sendall(nonce.encode())
        
        client_hash = client_socket.recv(BUFFER_SIZE).decode().strip()
        expected_str = nonce + shared_secret
        expected_hash = hashlib.sha256(expected_str.encode()).hexdigest()

        if client_hash == expected_hash:
            client_socket.sendall("AUTH_SUCCESS".encode())
            with auth_lock:
                if username in login_attempts: del login_attempts[username]
        else:
            msg = ""
            with auth_lock:
                login_attempts[username] = login_attempts.get(username, 0) + 1
                if login_attempts[username] >= 3:
                    blocked_users[username] = True
                    msg = "AUTH_FAIL: Account Blocked"
                else:
                    msg = "AUTH_FAIL: Incorrect Credentials"
            client_socket.sendall(msg.encode())
            client_socket.close()
            return

        # --- PHASE 2: DH KEY EXCHANGE ---
        dh_data = client_socket.recv(BUFFER_SIZE).decode().strip()
        P_str, G_str, A_str = dh_data.split(',')
        P, G, A = int(P_str), int(G_str), int(A_str)
        
        # Verify inputs (optional debug)
        print(f"[DEBUG] Server received: P={P}, G={G}") 

        b = secrets.randbelow(P - 1) + 1
        B = pow(G, b, P)
        session_int = pow(A, b, P)
        session_key = str(session_int)
        
        client_socket.sendall(str(B).encode())
        print(f"[SECURE] Session Key established for {username}.")

        # --- PHASE 3: COMMANDS ---
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data: break
            
            command_line = data.decode('utf-8').strip()
            parts = command_line.split()
            if not parts: continue
            
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            response = ""

            if cmd == "LIST":
                try:
                    files = [f for f in os.listdir('.') if os.path.isfile(f)]
                    response = " ".join(files) if files else "Empty Directory"
                    client_socket.sendall(response.encode())
                except: 
                    client_socket.sendall("ERROR".encode())
            
            elif cmd == "INFO" and arg:
                 if os.path.exists(arg):
                    st = os.stat(arg)
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    ctime = datetime.datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    response = f"Size: {st.st_size} bytes, Perms: {oct(st.st_mode)[-3:]}, Modified: {mtime}, Created: {ctime}"
                 else: response = "ERROR: File not found"
                 client_socket.sendall(response.encode())

            elif cmd == "GETSIZE" and arg:
                if os.path.exists(arg): response = f"{os.path.getsize(arg)} bytes"
                else: response = "ERROR: File not found"
                client_socket.sendall(response.encode())

            elif cmd == "GET" and arg:
                # Task 3: Handle File Download
                response = handle_get_command(client_socket, arg, session_key)
                # Note: handle_get_command does its own sending, so we don't sendall here
                # We just log the result

            elif cmd == "QUIT":
                log_event(command_line, "Connection Terminated")
                break
            else:
                response = "ERROR: Invalid Command"
                client_socket.sendall(response.encode())

            log_event(command_line, response)

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
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()