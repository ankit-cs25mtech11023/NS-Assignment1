import socket
import threading
import os
import datetime
import hashlib
import secrets
# REQUIRED: pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
HOST = '0.0.0.0'
PORT = 8080
BUFFER_SIZE = 4096
CREDENTIALS_FILE = "credentials.txt"
LOG_FILE = "server.log"
CHUNK_SIZE = 1024  

# Locks
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

# --- CRYPTO HELPERS [cite: 101, 102] ---
def derive_aes_key(session_key):
    """Derives a 128-bit AES key from the session key using SHA-256."""
    # Ensure session_key is bytes
    if isinstance(session_key, int):
        session_key = str(session_key)
    key_hash = hashlib.sha256(session_key.encode()).digest()
    return key_hash[:16] # Take first 16 bytes for AES-128

def encrypt_data(data, aes_key):
    """Encrypts data using AES-CBC with a random IV."""
    # Generate random IV
    iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    if isinstance(data, str):
        data = data.encode()
    # Pad data to block size (16 bytes)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    # Return IV + Ciphertext (so receiver can decrypt)
    return iv + ciphertext

def decrypt_data(encrypted_data, aes_key):
    """Decrypts data (expects IV + Ciphertext)."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    return unpad(padded_data, AES.block_size)

def calculate_mac_encrypted(enc_data, seq_no, session_key):
    """Calculates MAC = HASH(ENC_DATA || SEQ_NO || SESSION_KEY) [cite: 113]"""
    seq_bytes = str(seq_no).encode('utf-8')
    key_bytes = str(session_key).encode('utf-8')
    payload = enc_data + seq_bytes + key_bytes
    return hashlib.sha256(payload).hexdigest()

# --- FILE TRANSFER ---
def handle_get_command(client_socket, filename, aes_key, session_key):
    if not os.path.exists(filename):
        # Encrypt the error message
        err = encrypt_data("FILE NOT AVAILABLE", aes_key)
        client_socket.sendall(err)
        return "FILE NOT AVAILABLE"

    # 1. Send File Found (Encrypted)
    file_size = os.path.getsize(filename)
    msg = f"FILE_FOUND {file_size}"
    client_socket.sendall(encrypt_data(msg, aes_key))
    
    seq_no = 0
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # 2. Encrypt Chunk [cite: 112]
            # ENC(DATA) = IV + AES(PAD(DATA))
            enc_chunk = encrypt_data(chunk, aes_key)
            
            # 3. Calculate MAC [cite: 113]
            # MAC = HASH(ENC_DATA || SEQ_NO || SESSION_KEY)
            mac = calculate_mac_encrypted(enc_chunk, seq_no, session_key)
            
            # 4. Construct Packet 
            # SEQ_NO (4) + LEN_ENC (4) + ENC_DATA + MAC (64)
            # We need length of encrypted data because it varies with padding
            header = seq_no.to_bytes(4, 'big') + len(enc_chunk).to_bytes(4, 'big')
            packet = header + enc_chunk + mac.encode()
            
            client_socket.sendall(packet)
            seq_no += 1
            
    # Send EOF Packet
    # Data length 0 implies end
    end_header = seq_no.to_bytes(4, 'big') + (0).to_bytes(4, 'big')
    # Dummy MAC
    dummy_mac = calculate_mac_encrypted(b"", seq_no, session_key).encode()
    client_socket.sendall(end_header + dummy_mac)
    
    return f"File {filename} sent ({file_size} bytes)"

# --- MAIN SERVER LOGIC ---
def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    session_key = None
    aes_key = None
    username = None
    
    try:
        # === PHASE 1: AUTH (Plaintext) ===
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
        expected_hash = hashlib.sha256((nonce + shared_secret).encode()).hexdigest()

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

        # === PHASE 2: DH EXCHANGE (Plaintext) ===
        dh_data = client_socket.recv(BUFFER_SIZE).decode().strip()
        P_str, G_str, A_str = dh_data.split(',')
        P, G, A = int(P_str), int(G_str), int(A_str)

        b = secrets.randbelow(P - 1) + 1
        B = pow(G, b, P)
        session_int = pow(A, b, P)
        session_key = str(session_int)
        
        # Derive AES Key 
        aes_key = derive_aes_key(session_key)
        
        client_socket.sendall(str(B).encode())
        print(f"[SECURE] Session Key established for {username}. Switching to AES.")

        # === PHASE 3: ENCRYPTED COMMANDS [cite: 99] ===
        while True:
            # 1. Receive Encrypted Command
            # First, read generic buffer (assuming command fits in one packet)
            # In a real streaming protocol, we'd send length headers. 
            # For this assignment, we assume simple commands fit in BUFFER_SIZE
            enc_data = client_socket.recv(BUFFER_SIZE)
            if not enc_data: break
            
            try:
                command_line = decrypt_data(enc_data, aes_key).decode().strip()
            except Exception as e:
                print(f"Decryption Error: {e}")
                continue

            parts = command_line.split()
            if not parts: continue
            
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            response = ""

            if cmd == "LIST":
                try:
                    files = [f for f in os.listdir('.') if os.path.isfile(f)]
                    response = " ".join(files) if files else "Empty Directory"
                except: response = "ERROR"
                # Encrypt and send
                client_socket.sendall(encrypt_data(response, aes_key))
            
            elif cmd == "INFO" and arg:
                 if os.path.exists(arg):
                    st = os.stat(arg)
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    ctime = datetime.datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    response = f"Size: {st.st_size} bytes, Perms: {oct(st.st_mode)[-3:]}, Modified: {mtime}, Created: {ctime}"
                 else: response = "ERROR: File not found"
                 client_socket.sendall(encrypt_data(response, aes_key))

            elif cmd == "GETSIZE" and arg:
                if os.path.exists(arg): response = f"{os.path.getsize(arg)} bytes"
                else: response = "ERROR: File not found"
                client_socket.sendall(encrypt_data(response, aes_key))

            elif cmd == "GET" and arg:
                # Handle File Download (Special Packet Loop)
                response = handle_get_command(client_socket, arg, aes_key, session_key)

            elif cmd == "QUIT":
                log_event(command_line, "Connection Terminated")
                break
            else:
                response = "ERROR: Invalid Command"
                client_socket.sendall(encrypt_data(response, aes_key))

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