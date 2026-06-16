### Theoretical Security Analysis
## Confidentiality (Data-at-Rest & Data-in-Transit Protection)
The Problem: Attackers monitoring the network interface (127.0.0.1:65432) could read the file data via simple packet sniffing if it were transmitted as cleartext.

Our Solution: The application utilizes a hybrid cryptosystem combining AES-256-GCM and RSA-2048.

Every file transfer triggers the generation of a pseudo-random, one-time-use symmetric Session Key via AESGCM.generate_key(bit_length=256).

Even if a hostile actor intercepts the network packet stream, they only capture the randomized AES ciphertext blocks. The data is entirely unreadable without the specific session key.

To securely transmit this session key to Bob, Alice wraps it inside an RSA asymmetric envelope encrypted with Bob's Public Key. Because of the properties of RSA asymmetry, only Bob's corresponding Private Key can decrypt and extract this session key.

## Integrity (Tamper Detection)
The Problem: An attacker could modify byte sequences while the data travels through the server, injecting malicious data or corrupting the files.

Our Solution: The codebase leverages SHA-256 secure hashing integrated with Galois/Counter Mode (GCM).

Before encryption, Alice calculates a fixed-size cryptographic fingerprint of the document using SHA-256.

During symmetric operations, AES-GCM produces an authenticated ciphertext block along with a validation tag. If even a single bit of the file payload is modified during socket transport or memory forwarding, the internal tag check in crypto_core.decrypt_file_aes() fails instantly, throwing an error and dropping the payload before it ever reaches the filesystem layer.

## Authentication & Non-Repudiation (Identity Verification)
The Problem: An attacker could log into the server, pretend to be Alice, and send Bob a malicious file. Alternatively, Alice could send a file and later falsely claim she never sent it.

Our Solution: Your application implements RSA Digital Signatures using Probabilistic Signature Scheme (PSS) padding.

Alice takes the SHA-256 file hash and encrypts it using her own Private Key (alice_private.pem). This generates a unique digital signature appended directly to the network payload.

When Bob receives the package, he extracts the signature and validates it using Alice's openly accessible Public Key (alice_public.pem).

Because Alice's Private Key is secret and uniquely owned by her, no one else can generate a valid signature matching her identity. This proves beyond doubt that Alice was the source (Authentication) and prevents her from denying the transaction (Non-Repudiation).