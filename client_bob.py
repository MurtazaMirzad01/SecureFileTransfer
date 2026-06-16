import socket
import struct
import crypto_core

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432


def run_bob():
    print("--- Bob (Receiver Client) Starting ---")

    # 1. Load Cryptographic Keys
    try:
        bob_private = crypto_core.load_private_key("bob")
        alice_public = crypto_core.load_public_key("alice")
    except FileNotFoundError:
        print("[ERROR] Keys missing! Please generate keys first.")
        return

    # 2. Establish Socket Connection to Server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall("REGISTER:bob".encode('utf-8'))

        reg_response = client_socket.recv(1024).decode('utf-8')
        print(f"[SERVER REGISTRATION] {reg_response}")

        if "SUCCESS" not in reg_response:
            return

        print("[WAITING] Standing by for incoming file alerts from the routing server...")

        # 3. Stream Listener Loop
        while True:
            server_notice = client_socket.recv(1024).decode('utf-8')
            if not server_notice:
                print("[DISCONNECTED] Server connection terminated.")
                break

            if server_notice.startswith("INCOMING_FROM:"):
                # Notice Format: "INCOMING_FROM:sender_name:total_bytes"
                _, sender, size_str = server_notice.split(":")
                total_bytes = int(size_str)
                print(f"\n[ALERT] Incoming secure file package from user '{sender}' ({total_bytes} bytes).")

                # Signal readiness to swallow the data block
                client_socket.sendall("READY".encode('utf-8'))

                # Read total incoming payload block
                payload = b""
                while len(payload) < total_bytes:
                    chunk = client_socket.recv(min(total_bytes - len(payload), 4096))
                    if not chunk:
                        break
                    payload += chunk

                print(f"[DOWNLOAD COMPLETE] Received complete package stream stack. Processing cryptography...")

                # 4. Unpacking the Cryptographic Package
                # First 12 bytes hold our lengths header (3 integers x 4 bytes each = 12 bytes)
                len_key, len_nonce, len_sig = struct.unpack("!III", payload[:12])

                # Calculate index boundaries inside the byte block
                start_key = 12
                start_nonce = start_key + len_key
                start_sig = start_nonce + len_nonce
                start_cipher = start_sig + len_sig

                # Slice the exact binary chunks out
                encrypted_aes_key = payload[start_key:start_nonce]
                nonce = payload[start_nonce:start_sig]
                signature = payload[start_sig:start_cipher]
                ciphertext = payload[start_cipher:]

                # 5. Reverse Cryptography Pipeline (Verification & Decryption)
                try:
                    # A. Decrypt the Session Key using Bob's RSA Private Key
                    aes_key = crypto_core.decrypt_aes_key(bob_private, encrypted_aes_key)
                    print("  [✓] Step 1/4: Symmetric AES session key successfully decrypted via RSA Private Key.")

                    # B. Decrypt File Data using the extracted key and GCM nonce
                    decrypted_file_bytes = crypto_core.decrypt_file_aes(ciphertext, aes_key, nonce)
                    print("  [✓] Step 2/4: Ciphertext successfully decrypted using AES-GCM.")

                    # C. Calculate Hash of the decrypted plaintext data
                    recalculated_hash = crypto_core.calculate_sha256(decrypted_file_bytes)
                    print(f"  [✓] Step 3/4: Data hash recalculated locally: {recalculated_hash}")

                    # D. Verify Alice's digital signature against the recalculated hash
                    is_authentic = crypto_core.verify_signature(alice_public, recalculated_hash.encode('utf-8'),
                                                                signature)

                    if is_authentic:
                        print("  [✓] Step 4/4: Digital Signature VERIFIED! Sender identity authentic and trusted.")

                        # Save the decrypted contents to a new file
                        output_filename = "downloaded_secret_document.txt"
                        with open(output_filename, "wb") as out_f:
                            out_f.write(decrypted_file_bytes)
                        print(f"\n[SUCCESS] File received securely and saved as '{output_filename}'!")
                    else:
                        print("\n[CRITICAL SECURITY ALERT] Digital Signature Validation FAILED! Data is untrusted.")

                except Exception as crypto_error:
                    print(
                        f"\n[DECRYPTION FAILURE] Malformed encryption envelope or altered tracking token: {crypto_error}")

    except Exception as e:
        print(f"[SOCKET EXCEPTION] Connection dropped unexpectedly: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    run_bob()