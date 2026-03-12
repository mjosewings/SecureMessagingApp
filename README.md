# Secure Messaging App (RSA Key Exchange + AES Encryption + HMAC Integrity)

A small full‑stack messaging demo designed for **secure and reliable communication over a network**. It uses:

- **RSA-OAEP (SHA-256)** for **session key exchange**
- **AES-256-CBC** for **message confidentiality**
- **HMAC-SHA256** for **message integrity / tamper detection**

This is intended as a clear, auditable reference implementation for a “hybrid crypto” flow (public‑key for key exchange, symmetric crypto for bulk data).

## Architecture

- **Server** (`server/`): Express API that exposes a public key, accepts encrypted messages, verifies integrity, decrypts, and writes a small audit log used by metrics.
- **Client** (`client/`): Web dashboard (Vite) that fetches the server public key, encrypts and authenticates outgoing messages, and visualizes server-side metrics.

## Cryptographic protocol (what happens on send)

1. **Client generates** a random 32‑byte session key \(K\) and 16‑byte IV.
2. **Client encrypts** the plaintext payload using **AES-256-CBC** with \(K\) and IV.
3. **Client computes** **HMAC-SHA256** using \(K\) over a canonical string containing:
   - `department`, `studentId`, `ivB64`, `ciphertextB64`
4. **Client encrypts \(K\)** using the server’s RSA public key with **RSA-OAEP + SHA-256**.
5. **Client sends** `{ encKeyB64, ivB64, ciphertextB64, hmacB64, ...meta }` to the server.
6. **Server decrypts \(K\)** using its RSA private key, **verifies HMAC**, and only then **decrypts ciphertext**.

## Requirements

- Node.js (recommended: latest LTS)
- npm

## Quick start (local dev)

Install dependencies from the repo root:

```bash
npm install
```

Run both server and client in parallel:

```bash
npm run dev
```

Endpoints:

- **Server**: `http://127.0.0.1:8000`
  - `GET /public-key`
  - `POST /messages`
  - `GET /metrics`
- **Client**: Vite prints a local URL (typically `http://localhost:5173/`)

## Scripts

From the repo root:

- `npm run dev`: run server + client together
- `npm run dev:server`: run only the API server
- `npm run dev:client`: run only the UI

## API contract

### `GET /public-key`

Returns the server’s RSA public key in PEM format (`text/plain`).

### `POST /messages`

Accepts an encrypted message payload.

**Request JSON**

- `department` (string)
- `studentId` (string)
- `name` (string, optional)
- `email` (string, optional)
- `ivB64` (string) — base64 16-byte IV
- `ciphertextB64` (string) — base64 AES ciphertext
- `encKeyB64` (string) — base64 RSA‑OAEP encrypted 32-byte session key
- `hmacB64` (string) — base64 HMAC-SHA256 over the canonical string
- `algo` (string, optional)
- `timestamp` (string, optional)

**Responses**

- `200`: `{ ok: true, received: { department, studentId }, length }`
- `400`: `{ ok: false, error }` for invalid payloads or failed HMAC verification
- `500`: `{ ok: false, error }` on server errors

### `GET /metrics`

Returns an aggregate view of server-side message logs for the dashboard (counts, series, latest list).

## Storage / logging

- Decrypted messages are appended to `server/storage.json` as a simple demo audit log.
- The dashboard reads aggregates via `GET /metrics` (the UI never reads `storage.json` directly).

## Security notes (read before using beyond a demo)

- This project is a **demo**; it is not a full secure messaging product.
- **AES-CBC + HMAC** is implemented correctly here (verify HMAC before decrypt), but modern designs often prefer **AEAD** (e.g., AES‑GCM or ChaCha20‑Poly1305) for simplicity and misuse resistance.
- There is **no identity/authentication** layer (no user accounts, no signing, no certificate pinning). Anyone can fetch the public key and submit ciphertexts.
- Key management is local-file based under `server/.keys/` (suitable for local dev, not production).

## Troubleshooting

- **Server not reachable**: verify `npm run dev` shows the server listening on port 8000.
- **UI loads but charts empty**: send at least one message; then `/metrics` will populate.
- **HMAC verification failed**: ensure the client and server compute HMAC over the same canonical string ordering and base64 values.


