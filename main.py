
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import json

from shared.crypto_utils import (
    generate_rsa_keypair, load_private_key, load_public_key,
    rsa_decrypt_oaep, b64d, aes_cbc_decrypt, hmac_verify_sha256
)
from server.storage import STORE, StoredMessage
from anomaly.heuristics import basic_anomaly_score

app = FastAPI(title="Secure Messaging Server", version="1.1.0")

PRIVATE_PEM, PUBLIC_PEM = generate_rsa_keypair()
PRIVATE_KEY = load_private_key(PRIVATE_PEM)
PUBLIC_KEY = load_public_key(PUBLIC_PEM)

class MessagePayload(BaseModel):
    client_id: str | None = None
    encrypted_key_b64: str
    iv_b64: str
    ciphertext_b64: str
    hmac_b64: str
    alg: Dict[str, str] | None = None
    timestamp: str | None = None

@app.get("/public-key")
def get_public_key():
    return {"public_key_pem": PUBLIC_PEM.decode("ascii")}

@app.post("/messages")
def receive_message(payload: MessagePayload):
    enc_key = b64d(payload.encrypted_key_b64)
    iv = b64d(payload.iv_b64)
    ct = b64d(payload.ciphertext_b64)
    mac = b64d(payload.hmac_b64)

    try:
        aes_key = rsa_decrypt_oaep(PRIVATE_KEY, enc_key)
    except Exception as e:
        raise HTTPException(400, f"RSA key decryption failed: {str(e)}")

    if not hmac_verify_sha256(aes_key, iv + ct, mac):
        raise HTTPException(400, "HMAC verification failed: message tampered or wrong key.")

    try:
        plaintext = aes_cbc_decrypt(aes_key, iv, ct)
    except Exception as e:
        raise HTTPException(400, f"AES decryption failed: {str(e)}")

    try:
        obj = json.loads(plaintext.decode("utf-8"))
        context = obj.get("context", {})
        message_text = context.get("message", "")
        sent_at = obj.get("sent_at", "")
        department = context.get("department", "Unknown")
        course_code = context.get("course_code", None)
        role = context.get("role", "Unknown")
        sender_name = context.get("sender_name", "Anonymous")
    except Exception as e:
        raise HTTPException(400, f"Invalid plaintext JSON: {str(e)}")

    score = basic_anomaly_score(message_text)
    flagged = score >= 1.5

    STORE.add(StoredMessage(
        client_id=payload.client_id or "anon",
        department=department,
        course_code=course_code,
        role=role,
        sender_name=sender_name,
        message=message_text,
        sent_at=sent_at,
        anomaly_score=score,
        flagged=flagged
    ))

    return {"status": "ok", "anomaly_score": score, "flagged": flagged, "received_len": len(message_text)}

@app.get("/messages")
def list_messages():
    return [m.__dict__ for m in STORE.all()]
