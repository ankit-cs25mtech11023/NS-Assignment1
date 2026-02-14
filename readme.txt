CS6903: Network Security - Programming Assignment 1
===================================================

GROUP MEMBERS
-------------
Name: Ambarish Sarkar
Roll Number: CS25MTECH11022

Name: Ankit Kr Sinha
Roll Number: CS25MTECH11023


CONTRIBUTION BREAKDOWN
----------------------
To ensure a balanced workload, we divided the tasks based on complexity:

Ambarish Sarkar (CS25MTECH11022):
  - Task 1 (Basic Architecture): Set up the initial client-server socket framework and implemented the basic command handling (LIST, INFO, QUIT).
  - Task 4 (Encryption - AES): Handled the most complex module, integrating 'pycryptodome' to implement AES-128 CBC encryption. This involved deriving keys from the session secret and ensuring all commands and file chunks were encrypted and decrypted correctly.
  - Report & Analysis: Led the Wireshark traffic analysis to demonstrate the transition from plaintext to ciphertext.

Ankit Kr Sinha (CS25MTECH11023):
  - Task 2 (Auth & Key Exchange): Implemented the multi-threading logic, the Challenge-Response authentication protocol, and the Diffie-Hellman Key Exchange to establish the shared secret.
  - Task 3 (Integrity & Protocol Design): Designed the binary file transfer protocol for the GET command. This included implementing the packet structure (Header + Data + MAC), calculating HMAC-SHA256 for integrity, and handling file reconstruction on the client side.
  - Error Handling: Implemented robust error handling for network disconnects and integrity failures.


PREREQUISITES & ENVIRONMENT SETUP
---------------------------------

1. System Requirements
   - Operating System: Linux (Ubuntu/Debian recommended).
   - Python Version: Python 3.6 or higher.

2. Virtual Environment (Recommended)
   It is highly recommended to run this assignment in a Python Virtual Environment to avoid conflicts and permission issues with external libraries.

   Commands:
     # 1. Create the virtual environment
     python3 -m venv venv

     # 2. Activate the environment
     source venv/bin/activate

     # 3. Install required libraries (for Task 4)
     pip install pycryptodome

3. Environment Variables
   For Task 2, 3, and 4, the client requires Diffie-Hellman parameters (P and G) to be set in the environment. Run the following commands in your terminal BEFORE starting the client:

   Commands:
     # Example using a safe prime (P) and generator (G)
     export P=99991
     export G=7

   Note: If you close the terminal, you must export these variables again.


EXECUTION INSTRUCTIONS
----------------------

Task 1: Basic File Management
  - Directory: Task1/
  - Description: Single-client, plain-text file server.
  - Execution:
      Server: python3 server.py
      Client: python3 client.py
  - Supported Commands: LIST, INFO <filename>, GETSIZE <filename>, QUIT.

Task 2: Multi-Client Authentication
  - Directory: Task2/
  - Description: Multi-threaded server with Auth & Session Key Establishment.
  - Execution:
      Server: python3 server.py
      Client: (Ensure P and G are exported) python3 client.py
  - Note: Use the credentials found in 'credentials.txt' to log in.

Task 3: Secure File Download (Integrity)
  - Directory: Task3/
  - Description: Adds GET <filename> with HMAC-SHA256 integrity checks.
  - Execution:
      Server: python3 server.py
      Client: python3 client.py
  - Test: Run 'GET test.txt'. If the file is received without error, integrity is verified.

Task 4: Encrypted Communication (Confidentiality)
  - Directory: Task4/
  - Description: Full AES-128 CBC encryption for commands and data.
  - Execution:
      Server: python3 server.py
      Client: python3 client.py
  - Observation: Output will show [Cipher]: <hex> and [Plain]: <text> when GET <filename> will be the input.


REFERENCES
----------

Technical References:
1. GeeksforGeeks - Socket Programming in Python:
   https://www.geeksforgeeks.org/socket-programming-python/

2. GeeksforGeeks - AES Encryption in Python:
   https://www.geeksforgeeks.org/advanced-encryption-standard-aes-python/

3. Python Official Docs - Socket Programming HOWTO:
   https://docs.python.org/3/howto/sockets.html

4. PyCryptodome Documentation (AES CBC Mode):
   https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode

Course Materials:
5. Course Slides: CS6903 Network Security - Cryptography and Secure Communication.
6. RFC 3526: Modular Exponential (MODP) Diffie-Hellman groups.