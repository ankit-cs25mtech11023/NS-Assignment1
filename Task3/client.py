import socket
import os
import sys
import hashlib
import secrets

# Configuration
HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 4096

def calculate_mac(data, seq_no, session_key):
    """Computes MAC for verification."""
    seq_bytes = str(seq_no).encode('utf-8')
    key_bytes = str(session_key).encode('utf-8')
    payload = data + seq_bytes + key_bytes
    return hashlib.sha256(payload).hexdigest()

def receive_n_bytes(sock, n):
    """Helper to ensure we get exactly n bytes from TCP stream"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def download_file(sock, filename, session_key):
    """
    Receives file chunks, verifies integrity, and writes to disk.
    """
    # 1. Check Server Response
    # The first response is either "FILE NOT AVAILABLE" or "FILE_FOUND <size>"
    # We peek or just read a small buffer. 
    # Since server sends strictly formatted packets AFTER this msg, we can just recv.
    
    # Wait for the initial status message
    initial_resp = sock.recv(BUFFER_SIZE).decode()
    
    if "FILE NOT AVAILABLE" in initial_resp:
        print(f"[OUTPUT] RESPONSE: FILE NOT AVAILABLE")
        return

    if not initial_resp.startswith("FILE_FOUND"):
        print(f"[ERROR] Unexpected server response: {initial_resp}")
        return

    print(f"[OUTPUT] RESPONSE: {initial_resp}")
    print("[INFO] Starting download with Integrity Verification...")
    
    # Output file name (prepend 'downloaded_' to avoid overwriting source if local)
    out_filename = f"downloaded_{filename}"
    
    expected_seq_no = 0
    
    with open(out_filename, 'wb') as f:
        while True:
            # 2. Read Header (8 bytes: 4 seq + 4 len)
            header = receive_n_bytes(sock, 8)
            if not header: break # Connection closed
            
            seq_no = int.from_bytes(header[:4], byteorder='big')
            data_len = int.from_bytes(header[4:], byteorder='big')
            
            # Check for End of Transmission (Length 0)
            if data_len == 0:
                # Consume the dummy MAC (64 bytes)
                _ = receive_n_bytes(sock, 64)
                print("[INFO] Download Complete. Integrity Verified.")
                break
            
            # 3. Read Data
            data = receive_n_bytes(sock, data_len)
            if data is None:
                print("[ERROR] Download interrupted. Aborting.")
                return
            
            # 4. Read MAC (64 bytes)
            mac_bytes = receive_n_bytes(sock, 64)
            if mac_bytes is None:
                print("[ERROR] Download interrupted while reading MAC. Aborting.")
                return
            
            received_mac = mac_bytes.decode('utf-8')

            
            
            # 5. Verify Integrity [cite: 90]
            # Calculate local MAC
            calculated_mac = calculate_mac(data, seq_no, session_key)
            
            if calculated_mac != received_mac:
                print(f"[ERROR] Integrity Check Failed at Block {seq_no}!")
                print("[ERROR] File corrupted. Aborting.")
                return # Abort download
            
            if seq_no != expected_seq_no:
                print(f"[ERROR] Out of order packet! Expected {expected_seq_no}, got {seq_no}")
                return

            # 6. Write to file if verified
            f.write(data)
            expected_seq_no += 1
            
    print(f"[SUCCESS] File saved as {out_filename}")

def start_client():
    try:
        P_val = int(os.environ.get("P", "23")) 
        G_val = int(os.environ.get("G", "5"))
        print(f"[DEBUG] Client loaded: P={P_val}, G={G_val}") 
    except ValueError:
        print("Error: Environment variables P and G must be integers.")
        return

    username = input("Enter Username: ")
    password = input("Enter Shared Secret: ") 

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((HOST, PORT))
        
        # --- PHASE 1: AUTH ---
        client.sendall(username.encode())
        nonce = client.recv(BUFFER_SIZE).decode()
        if "AUTH_FAIL" in nonce:
            print(f"Server Response: {nonce}")
            return

        expected_str = nonce + password
        auth_hash = hashlib.sha256(expected_str.encode()).hexdigest()
        client.sendall(auth_hash.encode())
        
        result = client.recv(BUFFER_SIZE).decode()
        if "AUTH_SUCCESS" not in result:
            print(f"Authentication Failed: {result}")
            return
        
        print("Authentication Successful!")

        # --- PHASE 2: DH KEY ---
        a = secrets.randbelow(P_val - 1) + 1
        A = pow(G_val, a, P_val)
        msg = f"{P_val},{G_val},{A}"
        client.sendall(msg.encode())
        
        B_str = client.recv(BUFFER_SIZE).decode()
        B = int(B_str)
        session_int = pow(B, a, P_val)
        session_key = str(session_int)
        
        print(f"Session Key Established: {session_key}")
        print("-" * 40)

        # --- PHASE 3: COMMANDS ---
        print("Commands: LIST, INFO <file>, GETSIZE <file>, GET <file>, QUIT")
        
        while True:
            cmd_line = input("[INPUT] ")
            if not cmd_line.strip(): continue
            
            client.sendall(cmd_line.encode())
            
            parts = cmd_line.split()
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "QUIT":
                break
            
            # Task 3: Special handling for GET response
            if cmd == "GET" and arg:
                download_file(client, arg, session_key)
            else:
                # Standard Text Response
                resp = client.recv(BUFFER_SIZE).decode()
                print(f"[OUTPUT] RESPONSE: {resp}")

    except ConnectionResetError:
        print("Connection closed by server.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()