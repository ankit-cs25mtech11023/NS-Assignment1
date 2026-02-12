import socket
import os
import time
import datetime
import stat

# Configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 8080
BUFFER_SIZE = 4096
LOG_FILE = "server.log"
 
def log_event(command, response):
    """Logs requests and responses to server.log with timestamp."""
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    
    log_resp = response
    
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} REQUEST: {command}\n")
        f.write(f"{timestamp} RESPONSE: {log_resp}\n")

def handle_list():
    """Returns a space-separated list of files in the current directory."""
    try:
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        return " ".join(files) if files else "Empty Directory"
    except Exception as e:
        return f"ERROR: {str(e)}"

def handle_info(filename):
    """Returns file size, permissions, last modified, and creation time."""
    if not os.path.exists(filename):
        return "ERROR: File not found"
    
    try:
        stats = os.stat(filename)
        
        # 1. Size
        size = f"{stats.st_size} bytes"
        
        # 2. Permissions (Convert mode to rwx)
        mode = stats.st_mode
        perms = ""
        perms += "r" if mode & stat.S_IRUSR else "-"
        perms += "w" if mode & stat.S_IWUSR else "-"
        perms += "x" if mode & stat.S_IXUSR else "-"
        
        # 3. Timestamps
        mtime = datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        ctime = datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        
        return f"Size: {size}, Permissions: {perms}, Last Modified: {mtime}, Created: {ctime}"
    except Exception as e:
        return f"ERROR: {str(e)}"

def handle_getsize(filename):
    """Returns the size of the file in bytes."""
    if not os.path.exists(filename):
        return "ERROR: File not found"
    return f"{os.path.getsize(filename)} bytes"

def start_server():
    # 1. Create Socket (AF_INET=IPv4, SOCK_STREAM=TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow immediate reuse of the port after stopping the server
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # 2. Bind and Listen
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) # Backlog of 5
        print(f"Server listening on port {PORT}...")
        
        while True:
            # 3. Accept Connection
            client_socket, addr = server_socket.accept()
            # print(f"Connection from {addr}")
            
            with client_socket:
                while True:
                    # 4. Receive Data
                    data = client_socket.recv(BUFFER_SIZE)
                    if not data:
                        break # Client disconnected
                    
                    command_line = data.decode('utf-8').strip()
                    parts = command_line.split()
                    
                    if not parts:
                        continue
                        
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ""
                    response = ""
                    
                    # 5. Process Commands
                    if cmd == "LIST":
                        response = handle_list()
                    elif cmd == "INFO" and arg:
                        response = handle_info(arg)
                    elif cmd == "GETSIZE" and arg:
                        response = handle_getsize(arg)
                    elif cmd == "QUIT":
                        log_event(command_line, "Connection Terminated")
                        break
                    else:
                        response = "ERROR: Invalid Command"
                    
                    # 6. Log and Send
                    log_event(command_line, response)
                    client_socket.sendall(response.encode('utf-8'))

    except KeyboardInterrupt:
        print("\nServer stopping...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()