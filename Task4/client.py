import socket
import os
import sys
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 4096

# --- CRYPTO HELPERS ---
def derive_aes_key(session_key):
    if isinstance(session_key, int):
        session_key = str(session_key)
    key_hash = hashlib.sha256(session_key.encode()).digest()
    return key_hash[:16]

def encrypt_data(data, aes_key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    if isinstance(data, str): data = data.encode()
    return iv + cipher.encrypt(pad(data, AES.block_size))

def decrypt_data(encrypted_data, aes_key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def calculate_mac_encrypted(enc_data, seq_no, session_key):
    seq_bytes = str(seq_no).encode('utf-8')
    key_bytes = str(session_key).encode('utf-8')
    payload = enc_data + seq_bytes + key_bytes
    return hashlib.sha256(payload).hexdigest()

def receive_n_bytes(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

def download_file_encrypted(sock, filename, aes_key, session_key):
    # 1. Receive Initial Response (Encrypted)
    # We assume the initial status message fits in the buffer
    enc_resp = sock.recv(BUFFER_SIZE)
    try:
        resp = decrypt_data(enc_resp, aes_key).decode()
        
        # Display Cipher/Plain as requested 
        print(f"[Cipher]: {enc_resp.hex()[:60]}...") # Truncate for display
        print(f"[Plain]:  {resp}")
        
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    if "FILE NOT AVAILABLE" in resp:
        return

    print("[INFO] Starting Encrypted Download...")
    out_filename = f"downloaded_{filename}"
    expected_seq_no = 0
    
    with open(out_filename, 'wb') as f:
        while True:
            # 2. Read Header: SEQ (4) + LEN (4)
            header = receive_n_bytes(sock, 8)
            if not header: break
            
            seq_no = int.from_bytes(header[:4], 'big')
            enc_len = int.from_bytes(header[4:], 'big')
            
            if enc_len == 0:
                _ = receive_n_bytes(sock, 64) # Consume dummy MAC
                print("[INFO] Download Complete. Integrity Verified.")
                break
                
            # 3. Read Encrypted Data
            enc_data = receive_n_bytes(sock, enc_len)
            if enc_data is None: break
            
            # 4. Read MAC
            mac_bytes = receive_n_bytes(sock, 64)
            if mac_bytes is None: break
            received_mac = mac_bytes.decode()
            
            # 5. Verify MAC First (Encrypt-then-MAC) [cite: 114]
            calc_mac = calculate_mac_encrypted(enc_data, seq_no, session_key)
            
            if calc_mac != received_mac:
                print(f"[ERROR] Integrity Check Failed at Block {seq_no}")
                return
            
            # 6. Decrypt
            try:
                plaintext_chunk = decrypt_data(enc_data, aes_key)
                f.write(plaintext_chunk)
            except Exception as e:
                print(f"[ERROR] Decryption Failed at Block {seq_no}: {e}")
                return

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
    aes_key = None
    
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
        
        # Derive AES Key
        aes_key = derive_aes_key(session_key)
        print(f"Session Key Established. AES Key Derived.")
        print("-" * 40)

        # --- PHASE 3: ENCRYPTED COMMANDS ---
        print("Commands: LIST, INFO <file>, GETSIZE <file>, GET <file>, QUIT")
        
        while True:
            cmd_line = input("[INPUT] ")
            if not cmd_line.strip(): continue
            
            # Encrypt Command [cite: 103]
            enc_cmd = encrypt_data(cmd_line, aes_key)
            client.sendall(enc_cmd)
            
            parts = cmd_line.split()
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "QUIT":
                break
            
            if cmd == "GET" and arg:
                download_file_encrypted(client, arg, aes_key, session_key)
            else:
                # Standard Response
                enc_resp = client.recv(BUFFER_SIZE)
                try:
                    resp = decrypt_data(enc_resp, aes_key).decode()
                    # Output Format 
                    print(f"[Cipher]: {enc_resp.hex()[:60]}...") 
                    print(f"[Plain]:  {resp}")
                except Exception as e:
                    print(f"Error receiving response: {e}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()