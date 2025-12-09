
import argparse, sys, os, requests
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path: sys.path.append(ROOT)

from shared.models import CampusMessage, serialize_campus_message
from shared.crypto_utils import (
    load_public_key, rsa_encrypt_oaep, generate_aes_key_iv,
    aes_cbc_encrypt, hmac_sha256, b64e
)

def fetch_server_public_key(base_url: str) -> str:
    r = requests.get(f"{base_url}/public-key", timeout=10)
    r.raise_for_status()
    return r.json()["public_key_pem"]

def build_secure_payload(pub_pem: str, plaintext_json: str, client_id: str | None = None) -> dict:
    public_key = load_public_key(pub_pem.encode("ascii"))
    aes_key, iv = generate_aes_key_iv()
    ciphertext = aes_cbc_encrypt(aes_key, iv, plaintext_json.encode("utf-8"))
    mac = hmac_sha256(aes_key, iv + ciphertext)
    enc_key = rsa_encrypt_oaep(public_key, aes_key)
    return {
        "client_id": client_id,
        "encrypted_key_b64": b64e(enc_key),
        "iv_b64": b64e(iv),
        "ciphertext_b64": b64e(ciphertext),
        "hmac_b64": b64e(mac),
        "alg": {"rsa":"RSA-OAEP-SHA256","aes":"AES-256-CBC","hmac":"HMAC-SHA256"}
    }

def main():
    p = argparse.ArgumentParser(description="Secure Campus Client (CLI)")
    p.add_argument("--server", default="http://127.0.0.1:8000")
    p.add_argument("--client-id", default="client-001")
    p.add_argument("--department", default="Computer Science")
    p.add_argument("--role", default="Professor")
    p.add_argument("--sender-name", default="Dr. Elangovan")
    p.add_argument("--semester", default="Spring 2026")
    p.add_argument("--course-code", default="CMPSC 446")
    p.add_argument("--message", default="Hello from secure campus client!")
    args = p.parse_args()

    pub_pem = fetch_server_public_key(args.server)
    msg = CampusMessage(
        department=args.department, role=args.role, sender_name=args.sender_name,
        semester=args.semester, course_code=args.course_code, message=args.message
    )
    plaintext_json = serialize_campus_message(msg, client_id=args.client_id)
    payload = build_secure_payload(pub_pem, plaintext_json, client_id=args.client_id)
    resp = requests.post(f"{args.server}/messages", json=payload, timeout=10); resp.raise_for_status()
    print("Server response:", resp.json())

if __name__ == "__main__":
   main()