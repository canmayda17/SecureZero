# SecureZero: Zero-Trust File Drop System

SecureZero is a simple Python implementation of the CSE4057 secure file drop assignment. It uses a custom TCP application protocol, a toy CA, mutual certificate authentication, session-key derivation, encrypted upload/download, digital signatures, access control, expiration checks, replay protection, and security-aware logging.

The server stores encrypted file packages and routing metadata, but it never receives plaintext file contents or plaintext file keys.

## Setup

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Create demo keys and certificates:

```bash
python ca.py demo --overwrite
```

This creates a local `pki/` directory with CA, server, Alice, Bob, and Mallory credentials. Private keys are unencrypted because this is a course demo; do not use this key storage style in production.

## Run

Start the server:

```bash
python server.py --host 127.0.0.1 --port 9000
```

Upload from Alice to Bob:

```bash
python client.py --id alice upload --to bob --file samples/hello.txt --expires-in 3600
```

List Bob's available files:

```bash
python client.py --id bob list
```

Download as Bob:

```bash
python client.py --id bob download --file-id <file-id> --out downloads/hello_from_alice.txt
```

Try unauthorized access as Mallory:

```bash
python client.py --id mallory download --file-id <file-id> --out downloads/mallory.txt
```

Try expiration with a short-lived upload:

```bash
python client.py --id alice upload --to bob --file samples/hello.txt --expires-in 1
```

Wait a few seconds, then attempt to download that new file as Bob. The server rejects it and logs the expiration event.

## Project Structure

- `ca.py`: creates the CA and issues CA-signed certificates.
- `crypto_utils.py`: RSA, AES-GCM, HKDF, signatures, certificate verification, framing, secure session helpers.
- `server.py`: threaded TCP server, handshake, authentication, access control, expiration, logging.
- `client.py`: CLI client for upload, list, and download.
- `storage.py`: JSON metadata and encrypted package storage.
- `samples/hello.txt`: small demo file.
- `tests/`: lightweight crypto helper tests.

Generated runtime directories:

- `pki/`: CA, server, and client keys/certificates.
- `server_data/`: metadata and encrypted file packages.
- `logs/`: server/client logs.
- `downloads/`: downloaded plaintext files created by clients.

## Certificate Authority

Each identity has an RSA-2048 private key and a JSON certificate. Certificates contain:

- `subject_id`
- `public_key_pem`
- `issuer`
- `serial`
- `not_before`
- `not_after`
- `signature`

The CA signs the canonical JSON certificate body with RSA-PSS/SHA-256. Clients and the server validate certificate signatures, validity time, and expected subject IDs before trusting public keys.

## Handshake and Session Keys

The implementation does not use TLS or secure-socket wrappers. It uses length-prefixed JSON frames:

```text
4-byte big-endian length || canonical JSON message
```

Handshake order:

1. Client sends `CLIENT_HELLO` with protocol version, crypto suite, client certificate, client nonce, and timestamp.
2. Server verifies the client certificate and sends `SERVER_HELLO` with server certificate, server nonce, and timestamp.
3. Client generates a 32-byte pre-master secret, encrypts it to the server public key with RSA-OAEP/SHA-256, and signs the handshake transcript with RSA-PSS/SHA-256.
4. Server verifies the client signature, decrypts the pre-master secret, and derives session keys.
5. Server sends encrypted `SERVER_FINISHED` with a server signature over the transcript hash and session ID.
6. Client verifies the server signature and sends encrypted `CLIENT_FINISHED` with a client signature.

HKDF-SHA-256 derives:

- one AES-GCM key for client-to-server messages,
- one AES-GCM key for server-to-client messages,
- a session ID.

After the handshake, all application messages are AES-GCM encrypted. The AES-GCM associated data includes message type, session ID, and sequence number.

## Protocol Messages

Plain handshake messages:

- `CLIENT_HELLO`
- `SERVER_HELLO`
- `CLIENT_KEY_EXCHANGE`

Encrypted post-handshake messages:

- `SERVER_FINISHED`
- `CLIENT_FINISHED`
- `UPLOAD`
- `LIST`
- `DOWNLOAD`
- `RESPONSE`
- `BYE`

All sensitive requests include a UUID `request_id`. The server rejects repeated request IDs during its runtime.

## File Encryption and Upload

For every upload, the sender:

1. Creates a random file ID.
2. Creates a fresh 256-bit AES-GCM file key.
3. Encrypts the file locally with AES-GCM.
4. Wraps the file key using the recipient's RSA public key and RSA-OAEP/SHA-256.
5. Hashes plaintext and ciphertext with SHA-256.
6. Signs the package metadata with RSA-PSS/SHA-256.

The signature covers sender ID, recipient ID, file ID, filename, upload time, expiration time, AES nonce, AES associated data, wrapped key, plaintext hash, ciphertext hash, and both certificates. The encrypted file content is protected by the signed ciphertext hash.

The server verifies the sender certificate, recipient certificate, sender identity, ciphertext hash, expiration time, and sender signature before storing the package.

## Retrieval and Access Control

The server stores visible routing metadata:

- file ID
- sender ID
- recipient ID
- filename
- upload timestamp
- expiration timestamp
- status
- download count

Only the sender or intended recipient can list relevant metadata. Only the intended recipient can download the encrypted package.

On download, the recipient:

1. Verifies the sender certificate.
2. Verifies the sender signature on the package.
3. Unwraps the file key with their private key.
4. Decrypts the file with AES-GCM.
5. Verifies the plaintext SHA-256 hash before writing the output file.

## Expiration

Expiration is stored in ISO-8601 UTC format in both metadata and the signed package. The server checks expiration before allowing retrieval. Expired files are rejected, metadata status is updated to `expired`, and the event is logged.

The client also checks expiration after download, so a malicious or buggy server cannot trick the client into accepting an expired package silently.

## Replay Protection

Replay can occur during handshakes, encrypted requests, or repeated uploads/downloads.

Defenses:

- Fresh nonces and timestamps appear in hello messages.
- The pre-master exchange is bound to the handshake transcript.
- `SERVER_FINISHED` and `CLIENT_FINISHED` signatures bind both peers to the session ID.
- Every encrypted session frame has a strict sequence number.
- AES-GCM associated data includes session ID, message type, and sequence number.
- Sensitive requests include UUID request IDs, and the server rejects repeated IDs during runtime.

## Logging

Logs are written under `logs/`:

- connection establishment
- certificate verification
- handshake completion
- upload events
- list/download events
- failed authentication
- failed authorization
- signature failures
- replay detection
- expiration denials

Logs intentionally do not include private keys, session keys, file keys, plaintext file contents, or decrypted output.

## Tests

After installing dependencies:

```bash
python -m unittest discover -s tests
```

Manual demo checklist:

1. CA issues certificates with `python ca.py demo --overwrite`.
2. Server starts and waits for connections.
3. Alice and Bob authenticate through the custom handshake.
4. Alice uploads an encrypted file for Bob.
5. Server verifies and stores only the encrypted package.
6. Bob lists available files.
7. Bob downloads, decrypts, and verifies Alice's signature.
8. Mallory is rejected when trying to download Bob's file.
9. Expired files are rejected.
10. Logs show all relevant events.

## Security Analysis and Limitations

This is a course-oriented implementation, not a production file-drop service.

Known limitations:

- Private keys are stored unencrypted in `pki/` for demo simplicity.
- The server can see routing metadata such as sender, recipient, filename, size, and timing.
- Request-ID replay memory is in-memory only, so a server restart forgets old request IDs.
- The CA identity verification step is simplified and local.
- There is no certificate revocation list.
- Large files are read into memory instead of chunked.
- The server marks download attempts in metadata but does not implement one-time download semantics.
- Compromised client private keys allow impersonation until certificates expire.

Possible countermeasures:

- Encrypt private keys with passphrases or OS key storage.
- Add certificate revocation and shorter certificate lifetimes.
- Persist replay caches for high-value request types.
- Encrypt optional metadata fields for recipients only.
- Add chunked transfer with per-chunk hashes and signed manifests.
- Add signed recipient acknowledgements.

## Group Work Template

Fill this before submission:

| Member | Student number | Responsibilities |
| --- | --- | --- |
| Name 1 | ID 1 | CA/certificates, README |
| Name 2 | ID 2 | server protocol, storage, logging |
| Name 3 | ID 3 | client upload/download, tests |

Coordination notes:

- Communication channel:
- Integration/merge method:
- Final testing owner:

## Submission

Submit a single zip containing source code, README, requirements, sample files, and optional screenshots or terminal output. The zip filename should include the full names of all group members.
