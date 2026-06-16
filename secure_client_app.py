import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import threading
import struct
import os

# Import our custom encryption module
import crypto_core

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

class SecureTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Transfer System")
        self.root.geometry("500x550")
        
        # State variables
        self.username = ""
        self.client_socket = None
        self.selected_file_path = ""
        
        # Build the initial Login Screen View
        self.create_login_screen()

    # ==========================================
    # SCREEN 1: LOGIN FRAME
    # ==========================================
    def create_login_screen(self):
        self.login_frame = tk.Frame(self.root, padx=20, pady=20)
        self.login_frame.pack(expand=True)
        
        title_label = tk.Label(self.login_frame, text="Secure File Transfer", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        user_label = tk.Label(self.login_frame, text="Enter Username (e.g., alice or bob):", font=("Arial", 10))
        user_label.pack(pady=5)
        
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12), width=25)
        self.username_entry.pack(pady=5)
        self.username_entry.focus()
        
        login_btn = tk.Button(self.login_frame, text="Connect to Server", bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), command=self.handle_login, width=20)
        login_btn.pack(pady=15)

    # ==========================================
    # SCREEN 2: MAIN DASHBOARD FRAME
    # ==========================================
    def create_dashboard_screen(self):
        self.login_frame.pack_forget()  # Hide login panel
        
        self.dashboard_frame = tk.Frame(self.root, padx=15, pady=15)
        self.dashboard_frame.pack(fill="both", expand=True)
        
        # Header Display
        header_text = f"Logged in as: {self.username.upper()}"
        header_lbl = tk.Label(self.dashboard_frame, text=header_text, font=("Arial", 12, "bold"), fg="#1976D2")
        header_lbl.pack(anchor="w", pady=5)
        
        # ------------------------------------------
        # Section A: File Selection Panel
        # ------------------------------------------
        file_lf = tk.LabelFrame(self.dashboard_frame, text=" 1. Select File to Send ", padx=10, pady=10)
        file_lf.pack(fill="x", pady=8)
        
        self.file_label = tk.Label(file_lf, text="No file selected...", textvar="", fg="grey", anchor="w", bg="white", relief="sunken", width=40)
        self.file_label.pack(side="left", padx=5, fill="x", expand=True)
        
        browse_btn = tk.Button(file_lf, text="Browse...", command=self.browse_file)
        browse_btn.pack(side="right", padx=5)

        # ------------------------------------------
        # Section B: Target Recipient Config
        # ------------------------------------------
        target_lf = tk.LabelFrame(self.dashboard_frame, text=" 2. Destination User ", padx=10, pady=10)
        target_lf.pack(fill="x", pady=8)
        
        tk.Label(target_lf, text="Send Destination Username:").pack(side="left", padx=5)
        self.target_entry = tk.Entry(target_lf, font=("Arial", 10), width=15)
        self.target_entry.pack(side="left", padx=5)
        
        # Default helper text
        default_target = "bob" if self.username == "alice" else "alice"
        self.target_entry.insert(0, default_target)

        # ------------------------------------------
        # Section C: Real-Time Security Status Logs
        # ------------------------------------------
        status_lf = tk.LabelFrame(self.dashboard_frame, text=" 3. Live Security Status Panel ", padx=10, pady=10)
        status_lf.pack(fill="both", expand=True, pady=8)
        
        # Checkbox graphic placeholders to meet section 7.4 metrics
        self.aes_status_var = tk.StringVar(value="⬜ Pending Task Encryption")
        self.rsa_status_var = tk.StringVar(value="⬜ Pending Key Wrapping")
        self.sig_status_var = tk.StringVar(value="⬜ Pending Integrity Sign-off")
        
        tk.Label(status_lf, textvariable=self.aes_status_var, font=("Arial", 9), anchor="w").pack(fill="x", pady=2)
        tk.Label(status_lf, textvariable=self.rsa_status_var, font=("Arial", 9), anchor="w").pack(fill="x", pady=2)
        tk.Label(status_lf, textvariable=self.sig_status_var, font=("Arial", 9), anchor="w").pack(fill="x", pady=2)
        
        # Status text logger area
        self.log_text = tk.Text(status_lf, height=6, bg="#F5F5F5", font=("Courier", 9), state="disabled")
        self.log_text.pack(fill="both", expand=True, pady=5)

        # ------------------------------------------
        # Section D: Execute Transfer Action
        # ------------------------------------------
        self.send_btn = tk.Button(self.dashboard_frame, text="🔐 Encrypt & Transfer File", bg="#1976D2", fg="white", font=("Arial", 11, "bold"), command=self.start_send_thread)
        self.send_btn.pack(fill="x", pady=5)

    # ==========================================
    # CONTROL AND UTILITY LOGIC ACTIONS
    # ==========================================
    def append_log(self, message):
        """Safely updates UI logging text container element."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.selected_file_path = filename
            # Display only basename file descriptor string
            self.file_label.config(text=os.path.basename(filename), fg="black")

    def handle_login(self):
        user_input = self.username_entry.get().strip().lower()
        if not user_input:
            messagebox.showerror("Error", "Username text window empty!")
            return
            
        self.username = user_input
        
        # Connect to background infrastructure loop
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            
            # Identity confirmation packet exchange
            self.client_socket.sendall(f"REGISTER:{self.username}".encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            
            if "SUCCESS" in response:
                self.create_dashboard_screen()
                # Spawn background processing listener to read unexpected inputs from server
                threading.Thread(target=self.receive_handler_loop, daemon=True).start()
            else:
                messagebox.showerror("Error", f"Server connection refused: {response}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not link to central server: {e}")

    # ==========================================
    # OUTBOUND TRANSMISSION LOGIC (Sender Mode)
    # ==========================================
    def start_send_thread(self):
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Select a payload file via Browser engine first.")
            return
        # Block button interactions during action
        self.send_btn.config(state="disabled")
        threading.Thread(target=self.execute_secure_send, daemon=True).start()

    def execute_secure_send(self):
        target_user = self.target_entry.get().strip().lower()
        
        try:
            self.aes_status_var.set("⏳ Compiling Symmetric Encryption...")
            self.rsa_status_var.set("⬜ Pending Key Wrapping")
            self.sig_status_var.set("⬜ Pending Integrity Sign-off")
            
            # 1. Read absolute file bytes
            with open(self.selected_file_path, "rb") as f:
                raw_bytes = f.read()
                
            # 2. Cryptographic steps using our core module
            alice_private = crypto_core.load_private_key(self.username)
            bob_public = crypto_core.load_public_key(target_user)
            
            file_hash = crypto_core.calculate_sha256(raw_bytes)
            signature = crypto_core.sign_data(alice_private, file_hash.encode('utf-8'))
            self.sig_status_var.set("✅ Checksum Digitally Signed (SHA-256/RSA)")
            
            aes_key, nonce, ciphertext = crypto_core.encrypt_file_aes(raw_bytes)
            self.aes_status_var.set("✅ Plaintext Encrypted under AES-256-GCM")
            
            encrypted_aes_key = crypto_core.encrypt_aes_key(bob_public, aes_key)
            self.rsa_status_var.set("✅ Envelope Wrapped using Target Public Key")
            
            # 3. Assemble binary envelope packet block
            header_pack = struct.pack("!III", len(encrypted_aes_key), len(nonce), len(signature))
            payload = header_pack + encrypted_aes_key + nonce + signature + ciphertext
            
            # 4. Talk to network sockets
            self.append_log(f"[OUTBOUND] Requesting transfer window path to {target_user}...")
            self.client_socket.sendall(f"SEND_TO:{target_user}:{len(payload)}".encode('utf-8'))
            
            # We must be careful: the reader background thread is running, 
            # so network reads are globally synchronized inside the reader loop.
            # This method directly uploads payload data to socket pipe.
            
        except FileNotFoundError:
            self.append_log("[CRITICAL ERROR] RSA security certificates matching identity parameters missing!")
            self.reset_status_indicators()
        except Exception as e:
            self.append_log(f"[SYS ERROR] Execution breakdown occurred: {e}")
            self.reset_status_indicators()

    def reset_status_indicators(self):
        self.send_btn.config(state="normal")

    # ==========================================
    # INBOUND RECEIVING HANDLER LOOP (Continuous Background Thread)
    # ==========================================
    def receive_handler_loop(self):
        """Listens indefinitely for incoming payload routing flags from server."""
        try:
            while True:
                header_signal = self.client_socket.recv(1024).decode('utf-8')
                if not header_signal:
                    break
                    
                # Scenario A: Server accepts sender request block allocation
                if header_signal == "READY":
                    self.append_log("[NETWORK] Server ready buffer open. Pushing stream payload...")
                    # This triggers if we were in the middle of executing a send request
                    target_user = self.target_entry.get().strip().lower()
                    with open(self.selected_file_path, "rb") as f:
                        raw_bytes = f.read()
                    alice_private = crypto_core.load_private_key(self.username)
                    bob_public = crypto_core.load_public_key(target_user)
                    file_hash = crypto_core.calculate_sha256(raw_bytes)
                    signature = crypto_core.sign_data(alice_private, file_hash.encode('utf-8'))
                    aes_key, nonce, ciphertext = crypto_core.encrypt_file_aes(raw_bytes)
                    encrypted_aes_key = crypto_core.encrypt_aes_key(bob_public, aes_key)
                    header_pack = struct.pack("!III", len(encrypted_aes_key), len(nonce), len(signature))
                    payload = header_pack + encrypted_aes_key + nonce + signature + ciphertext
                    self.client_socket.sendall(payload)
                    
                elif header_signal == "TRANSFER_COMPLETE":
                    self.append_log("[SUCCESS] Encryption payload safely transmitted to destination hub.")
                    self.root.after(0, lambda: messagebox.showinfo("Success", "File transmission completed securely!"))
                    self.root.after(0, self.reset_status_indicators)
                    
                elif header_signal.startswith("ERROR:"):
                    self.append_log(f"[SERVER RESPONSE] {header_signal}")
                    self.root.after(0, lambda: messagebox.showerror("Transfer Error", header_signal))
                    self.root.after(0, self.reset_status_indicators)

                # Scenario B: Incoming transmission routing alert from another client (Receiver Mode)
                elif header_signal.startswith("INCOMING_FROM:"):
                    _, sender, size_str = header_signal.split(":")
                    total_bytes = int(size_str)
                    
                    self.root.after(0, lambda: self.append_log(f"[INCOMING ALERT] File found from '{sender}' ({total_bytes} bytes). Processing..."))
                    
                    # Accept handshake
                    self.client_socket.sendall("READY".encode('utf-8'))
                    
                    # Track data pipeline allocation
                    payload_buffer = b""
                    while len(payload_buffer) < total_bytes:
                        chunk = self.client_socket.recv(min(total_bytes - len(payload_buffer), 4096))
                        if not chunk:
                            break
                        payload_buffer += chunk
                        
                    self.process_incoming_crypto_package(sender, payload_buffer)
                    
        except Exception as e:
            print(f"Background thread read interface shutdown hook: {e}")
        finally:
            self.client_socket.close()

    def process_incoming_crypto_package(self, sender, data_buffer):
        """Processes and decrypted an incoming encrypted package."""
        try:
            self.aes_status_var.set("⏳ Unwrapping incoming cryptograms...")
            self.rsa_status_var.set("⏳ Processing key envelope...")
            self.sig_status_var.set("⏳ Re-evaluating sender signature...")
            
            # Struct parsing offset positions
            len_key, len_nonce, len_sig = struct.unpack("!III", data_buffer[:12])
            
            start_key = 12
            start_nonce = start_key + len_key
            start_sig = start_nonce + len_nonce
            start_cipher = start_sig + len_sig
            
            encrypted_aes_key = data_buffer[start_key:start_nonce]
            nonce = data_buffer[start_nonce:start_sig]
            signature = data_buffer[start_sig:start_cipher]
            ciphertext = data_buffer[start_cipher:]
            
            # Decryption Pipeline Actions
            my_private_key = crypto_core.load_private_key(self.username)
            sender_public_key = crypto_core.load_public_key(sender)
            
            # A. Decrypt the Session Key
            aes_key = crypto_core.decrypt_aes_key(my_private_key, encrypted_aes_key)
            self.rsa_status_var.set("✅ RSA Session Key Envelope Verified")
            
            # B. Plaintext deciphering
            decrypted_plaintext = crypto_core.decrypt_file_aes(ciphertext, aes_key, nonce)
            self.aes_status_var.set("✅ Plaintext recovered from AES-256-GCM")
            
            # C. Signature and hashing evaluations
            local_hash = crypto_core.calculate_sha256(decrypted_plaintext)
            signature_valid = crypto_core.verify_signature(sender_public_key, local_hash.encode('utf-8'), signature)
            
            if signature_valid:
                self.sig_status_var.set("✅ Digital Signature VERIFIED and trusted")
                
                # Prompt user for save destination frame location
                output_name = f"gui_received_from_{sender}.txt"
                with open(output_name, "wb") as f:
                    f.write(decrypted_plaintext)
                    
                self.append_log(f"[SUCCESS] Complete validation! Saved payload as '{output_name}'")
                self.root.after(0, lambda: messagebox.showinfo("Secure Receipt", f"New verified data payload safely saved as:\n{output_name}"))
            else:
                self.sig_status_var.set("❌ CRITICAL: Digital Signature FAILED!")
                self.append_log("[SECURITY FRAUD ALERT] Digital signature verification failed! Discarding payload data.")
                
        except Exception as err:
            self.append_log(f"[DECRYPTION ERROR] Malformed envelope payload processing failure: {err}")
            self.aes_status_var.set("❌ Cryptographic verification breakdown")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureTransferApp(root)
    root.mainloop()
