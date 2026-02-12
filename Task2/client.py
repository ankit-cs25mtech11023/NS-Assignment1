import socket
import os
import sys
import hashlib
import secrets

# Configuration
HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 4096

def start_client():
    # 1. Read Diffie-Hellman Parameters from Environment 
    # If not set, we default to small primes for testing (Assignment requires Env Vars)
    try:
        P_val = int(os.environ.get("P", "23")) # Default 23 for test
        G_val = int(os.environ.get("G", "5"))  # Default 5 for test
    except ValueError:
        print("Error: Environment variables P and G must be integers.")
        return

    # 2. Get User Credentials
    username = input("Enter Username: ")
    # In a real app, use getpass, but simple input is fine for this assignment
    password = input("Enter Shared Secret: ") 

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((HOST, PORT))
        
        # ==========================================
        # PHASE 1: AUTHENTICATION
        # ==========================================
        
        # 1. Send Username [cite: 55]
        client.sendall(username.encode())
        
        # 2. Receive Nonce
        nonce = client.recv(BUFFER_SIZE).decode()
        if "AUTH_FAIL" in nonce:
            print(f"Server Response: {nonce}")
            return

        # 3. Compute Hash: HASH(nonce || shared_secret) [cite: 57]
        expected_str = nonce + password
        auth_hash = hashlib.sha256(expected_str.encode()).hexdigest()
        
        # 4. Send Hash
        client.sendall(auth_hash.encode())
        
        # 5. Receive Auth Result
        result = client.recv(BUFFER_SIZE).decode()
        if "AUTH_SUCCESS" not in result:
            print(f"Authentication Failed: {result}")
            return
        
        print("Authentication Successful!")

        # ==========================================
        # PHASE 2: SESSION KEY (Diffie-Hellman) [cite: 65]
        # ==========================================
        
        # Client generates private key a
        a = secrets.randbelow(P_val - 1) + 1
        # Client computes Public Key A = (G^a) % P
        A = pow(G_val, a, P_val)
        
        # Send P, G, and A to server
        msg = f"{P_val},{G_val},{A}"
        client.sendall(msg.encode())
        
        # Receive Server's Public Key B
        B_str = client.recv(BUFFER_SIZE).decode()
        B = int(B_str)
        
        # Compute Session Key = (B^a) % P
        session_int = pow(B, a, P_val)
        session_key = str(session_int)
        
        print(f"Session Key Established: {session_key}")
        print("-" * 40)

        # ==========================================
        # PHASE 3: COMMAND LOOP
        # ==========================================
        print("Commands: LIST, INFO <file>, GETSIZE <file>, QUIT")
        
        while True:
            cmd = input("[INPUT] ")
            if not cmd.strip(): continue
            
            client.sendall(cmd.encode())
            
            if cmd.strip().upper() == "QUIT":
                break
                
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