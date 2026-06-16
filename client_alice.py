import socket
import struct
import crypto_core

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432


def run_alice():
    print("--- Alice (Sender Client) Starting ---")

    # 1. Load Cryptographic Keys
    try:
        alice_private = crypto_core.load_private_key("alice")
        bob_public = crypto_core.load_public_key("bob")
    except FileNotFoundError:
        print("[ERROR] Keys not found! Run 'test_crypto.py' first to generate them.")
        return

    # 2. Read the source file data
    file_path = "secret_document.txt"
    try:
        with open(file_path, "rb") as f:
            raw_file_bytes = f.read()
    except FileNotFoundError:
        print(f"[ERROR] {file_path} not found. Please create it first.")
        return

    print(f"[1. FILE READ] Loaded {len(raw_file_bytes)} bytes from {file_path}")

    # 3. Cryptography Operations (As per guidelines Section 5)
    # A. Calculate Integrity Checksum (SHA-256)
    file_hash = crypto_core.calculate_sha256(raw_file_bytes)
    print(f"[2. INTEGRITY] Computed file SHA-256: {file_hash}")

    # B. Sign the hash using Alice's Private Key (Authentication / Non-repudiation)
    signature = crypto_core.sign_data(alice_private, file_hash.encode('utf-8'))
    print(f"[3. AUTHENTICATION] Digitally signed the checksum. Signature size: {len(signature)} bytes")

    # C. Encrypt file data with a brand new random symmetric key (AES-256 GCM)
    aes_key, nonce, ciphertext = crypto_core.encrypt_file_aes(raw_file_bytes)
    print(f"[4. CONFIDENTIALITY] Encrypted file using AES-GCM. Ciphertext size: {len(ciphertext)} bytes")

    # D. Key Enveloping: Encrypt the temporary AES key with Bob's Public RSA Key
    encrypted_aes_key = crypto_core.encrypt_aes_key(bob_public, aes_key)
    print(f"[5. KEY WRAPPING] Encrypted AES Session key via Bob's RSA Public Key. Size: {len(encrypted_aes_key)} bytes")

    # 4. Construct the Network Payload Block
    # We prefix variables with their explicit lengths using struct.pack so Bob knows how to separate them.
    # Format 'I' means an unsigned integer (4 bytes)
    header_pack = struct.pack("!III", len(encrypted_aes_key), len(nonce), len(signature))

    # Complete binary payload assembly
    payload = header_pack + encrypted_aes_key + nonce + signature + ciphertext
    total_payload_size = len(payload)

    # 5. Connect and Transmit via Sockets
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        # Identity registration
        client_socket.sendall("REGISTER:alice".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        print(f"[SERVER REGISTRATION] {response}")

        if "SUCCESS" in response:
            # Inform server we want to route a package to bob
            transfer_header = f"SEND_TO:bob:{total_payload_size}"
            client_socket.sendall(transfer_header.encode('utf-8'))

            # Wait for server clearance acknowledgement
            ack = client_socket.recv(1024).decode('utf-8')
            if ack == "READY":
                print("[NETWORK] Server ready. Streaming secure cryptographic payload...")
                client_socket.sendall(payload)

                # Final confirmation from server
                result = client_socket.recv(1024).decode('utf-8')
                print(f"[NETWORK RESULT] Server reports: {result}")
            else:
                print(f"[NETWORK ERROR] Server denied transfer initialization: {ack}")

    except Exception as e:
        print(f"[SOCKET ERROR] Failed connection workflow: {e}")
    finally:
        client_socket.close()
        print("--- Alice Session Terminated Safely ---")


if __name__ == "__main__":
    run_alice()