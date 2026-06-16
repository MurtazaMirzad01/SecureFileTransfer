# Secure File Transfer System

A production-grade, secure hybrid-cryptographic file transmission ecosystem implemented in Python. The system facilitates end-to-end encrypted file distribution utilizing multi-threaded TCP socket architectures, a custom cryptographic pipeline, and an interactive Graphical User Interface (GUI).

This implementation satisfies core computer networking and advanced applied cryptography metrics—specifically guaranteeing the **CIA Triad (Confidentiality, Integrity, and Authentication)** under rigorous defensive engineering principles.

---

## 🏗️ Architectural Overview

The application features a **Centralized Routing Server Architecture** that decouples clients, allowing asynchronous discovery and routing without exposing peer devices directly to network edges.

### Data Transmission Package (Envelope Design)
To prevent transport-layer confusion, data is strictly structured into a sequential binary payload layout before hitting the wire:

1. **Header (12-bytes)**: Unsigned integers `!III` explicitly storing length parameters for the (Encrypted Session Key, Nonce, Signature).
2. **Key Envelope**: The AES key wrapped via RSA-2048.
3. **Initialization Vector / Nonce**: 12-byte cryptographically secure random sequence.
4. **Digital Signature**: Authoritative identity payload signed by the sender's Private Key.
5. **Ciphertext Block**: The core payload file protected under authenticated symmetric encryption.

---

## 🔒 Security Infrastructure & Defensive Engineering

### 1. Confidentiality (Data-at-Rest & In-Transit)
* **Symmetric Layer**: Files are encrypted with **AES-256 in Galois/Counter Mode (GCM)**. Every transmission generates a unique ephemeral session key using cryptographically secure random sources (`os.urandom`).
* **Asymmetric Key Wrapping**: Ephemeral session keys are encrypted using the recipient's **RSA-2048 Public Key** with **OAEP Padding** (using SHA-256). This restricts decryption access exclusively to the holder of the corresponding Private Key.

### 2. Integrity (Tamper Detection)
* Content mutations or mid-transit modification attacks are instantly intercepted. The system utilizes **SHA-256 secure hashing** alongside the intrinsic tag validation verification of **AES-GCM**. Any bit flips drop the payload before it can breach the filesystem.

### 3. Authentication & Non-Repudiation
* Senders digitally sign payload hashes using their **RSA-2048 Private Key** with **PSS Padding**. Recipients validate the signature against the sender's known Public Key, providing clear sender identity and non-repudiation constraints.

---

## 📂 Project Structure

```text
SecureFileTransfer/
│
├── venv/                       # Isolated Python Virtual Environment
├── .gitignore                  # Exclusion rules for local keys and caches
├── README.md                   # System presentation documentation
│
├── crypto_core.py              # Cryptographic Engine (AES-GCM, RSA, SHA-256)
├── server.py                   # Multi-Threaded TCP Routing Server
└── secure_client_app.py        # Unified Client Graphic Engine (Tkinter UI)