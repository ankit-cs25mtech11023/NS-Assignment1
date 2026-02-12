import socket
import sys

# Configuration
HOST = '127.0.0.1'  # Localhost
PORT = 8080
BUFFER_SIZE = 4096

def start_client():
    # 1. Create Socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # 2. Connect
        client_socket.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")
        print("Available commands: LIST, INFO <file>, GETSIZE <file>, QUIT")
        
        while True:
            # 3. Get Input
            user_input = input("[INPUT] ")
            
            if not user_input.strip():
                continue
                
            # 4. Send Command
            client_socket.sendall(user_input.encode('utf-8'))
            
            if user_input.strip().upper() == "QUIT":
                break
            
            # 5. Receive Response
            response = client_socket.recv(BUFFER_SIZE)
            print(f"[OUTPUT] RESPONSE: {response.decode('utf-8')}")
            
    except ConnectionRefusedError:
        print("Error: Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()