import socket
import threading

# Server Network Configuration Constants
HOST = '127.0.0.1'  # Localhost (Limits access to your local machine for safety)
PORT = 65432  # Arbitrary non-privileged port numbers > 1023

# A dictionary tracking connected clients: {'username': socket_connection}
connected_clients = {}


def handle_client(client_socket, client_address):
    """Handles all incoming messages and actions from a single connected client."""
    print(f"[NEW CONNECTION] Connected to client at address: {client_address}")
    username = None

    try:
        # Step A: First message received must identify who the client is (Registration)
        registration_message = client_socket.recv(1024).decode('utf-8')
        if registration_message.startswith("REGISTER:"):
            username = registration_message.split(":")[1].strip().lower()
            connected_clients[username] = client_socket
            print(f"[REGISTERED] Client '{username}' successfully linked to socket.")
            client_socket.send("SUCCESS: Registered".encode('utf-8'))
        else:
            client_socket.send("ERROR: Invalid identity prefix. Closing connection.".encode('utf-8'))
            client_socket.close()
            return

        # Step B: Keep listening for file payloads or communication from this client
        while True:
            # We look for a special command telling us a transmission is starting
            header = client_socket.recv(1024).decode('utf-8')
            if not header:
                break  # Client disconnected gracefully

            if header.startswith("SEND_TO:"):
                # Header syntax example: "SEND_TO:bob:payload_size"
                _, target_user, size_str = header.split(":")
                payload_size = int(size_str)
                print(
                    f"[TRANSFER REQUEST] {username} wants to send a secure file to {target_user} ({payload_size} bytes)")

                # Acknowledge sender readiness
                client_socket.send("READY".encode('utf-8'))

                # Receive the full encrypted block from the sender
                encrypted_payload = b""
                bytes_received = 0
                while bytes_received < payload_size:
                    chunk = client_socket.recv(min(payload_size - bytes_received, 4096))
                    if not chunk:
                        raise ConnectionError("Connection dropped during active transfer stream.")
                    encrypted_payload += chunk
                    bytes_received += len(chunk)

                # Step C: Routing payload to target user if they are currently online
                target_user = target_user.strip().lower()
                if target_user in connected_clients:
                    target_socket = connected_clients[target_user]
                    try:
                        # Forward payload initialization notice to target client
                        forward_header = f"INCOMING_FROM:{username}:{len(encrypted_payload)}"
                        target_socket.send(forward_header.encode('utf-8'))

                        # Wait for recipient confirmation acknowledgment
                        ack = target_socket.recv(1024).decode('utf-8')
                        if ack == "READY":
                            target_socket.sendall(encrypted_payload)
                            print(f"[FORWARD SUCCESS] Secure payload successfully routed to {target_user}.")
                            client_socket.send("TRANSFER_COMPLETE".encode('utf-8'))
                        else:
                            client_socket.send("ERROR: Recipient refused packet.".encode('utf-8'))
                    except Exception as e:
                        print(f"[FORWARD FAILED] Error transmitting payload to target: {e}")
                        client_socket.send("ERROR: Recipient connection unstable.".encode('utf-8'))
                else:
                    print(f"[TRANSFER FAILED] Destination user '{target_user}' is offline.")
                    client_socket.send("ERROR: Targeted recipient user is offline.".encode('utf-8'))

    except Exception as e:
        print(f"[SERVER EXCEPTION] Error handling communication loop for {username or client_address}: {e}")
    finally:
        # Clean up client reference when thread closes connection
        if username in connected_clients:
            del connected_clients[username]
        client_socket.close()
        print(f"[DISCONNECTED] Connection with {username or client_address} closed safely.")


def start_server():
    """Main function initializes socket binding and listens for incoming clients."""
    # Create an IPv4 (AF_INET) TCP (SOCK_STREAM) network socket engine
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Avoid 'Address already in use' system bugs on restarts
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[STARTING SERVER] Listening on {HOST}:{PORT}...")

    try:
        while True:
            # Code pauses here waiting for an incoming client to click connect
            client_socket, client_address = server_socket.accept()

            # Create an independent system thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True  # Allows thread to close automatically if main server exits
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[STOPPING SERVER] Server shutting down safely via administrator override command.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()