
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List
import json

from server.db import get_session, engine, Base
from server.models import Message
from anomaly.heuristics import basic_anomaly_score

from shared.crypto_utils import (
    generate_rsa_keypair, load_private_key, load_public_key,
    rsa_decrypt_oaep, b64d, aes_cbc_decrypt, hmac_verify_sha256
)

app = FastAPI(title="Secure Messaging Server (DB-backed)", version="2.0.0")

# Ensure tables exist (simple bootstrap)
Base.metadata.create_all(bind=engine)

PRIVATE_PEM, PUBLIC_PEM = generate_rsa_keypair()
PRIVATE_KEY = load_private_key(PRIVATE_PEM)
PUBLIC_KEY  = load_public_key(PUBLIC_PEM)

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
def receive_message(payload: MessagePayload, db=Depends(get_session)):
    # Decode & decrypt key
    enc_key = b64d(payload.encrypted_key_b64)
    iv      = b64d(payload.iv_b64)
    ct      = b64d(payload.ciphertext_b64)
    mac     = b64d(payload.hmac_b64)

    try:
        aes_key = rsa_decrypt_oaep(PRIVATE_KEY, enc_key)
    except Exception as e:
        raise HTTPException(400, f"RSA key decryption failed: {str(e)}")

    # Verify HMAC before decrypting
    if not hmac_verify_sha256(aes_key, iv + ct, mac):
        raise HTTPException(400, "HMAC verification failed: message tampered or wrong key.")

    #Decrypt & parse JSON
    try:
        plaintext = aes_cbc_decrypt(aes_key, iv, ct)
        obj = json.loads(plaintext.decode("utf-8"))
        ctx = obj.get("context", {})  # campus payload
        msg_text   = ctx.get("message", "")
        client_id  = obj.get("client_id", payload.client_id or "anon")
        sent_at    = obj.get("sent_at", "")
        department = ctx.get("department", "Unknown")
        role       = ctx.get("role", "Unknown")
        sender     = ctx.get("sender_name", "Anonymous")
        semester   = ctx.get("semester", "")
        course     = ctx.get("course_code", None)
    except Exception as e:
        raise HTTPException(400, f"Invalid plaintext JSON: {str(e)}")

    #Anomaly score
    score   = basic_anomaly_score(msg_text)
    flagged = score >= 1.5

    #Persist to DB
    row = Message(
        client_id=client_id,
        department=department, role=role, sender_name=sender,
        semester=semester, course_code=course,
        message=msg_text, sent_at=sent_at,
        anomaly_score=score, flagged=flagged
    )
    db.add(row); db.commit(); db.refresh(row)

    return {"status": "ok", "id": row.id, "anomaly_score": score, "flagged": flagged, "received_len": len(msg_text)}

@app.get("/messages")
def list_messages(limit: int = 100, db=Depends(get_session)) -> List[Dict[str, Any]]:
    q = db.query(Message).order_by(Message.id.desc()).limit(limit).all()
    return [ {
        "id": m.id,
        "client_id": m.client_id,
        "department": m.department,
        "role": m.role,
        "sender_name": m.sender_name,
        "semester": m.semester,
        "course_code": m.course_code,
        "message": m.message,
        "sent_at": m.sent_at,
        "anomaly_score": m.anomaly_score,
        "flagged": m.flagged,
        "created_at": m.created_at.isoformat() + "Z"
    } for m in q ]


@app.get("/messages/search")
def search_messages(
    department: str | None = None,
    semester: str | None = None,
    course_code: str | None = None,
    flagged: bool | None = None,
    db=Depends(get_session)
):
    q = db.query(Message)
    if department: q = q.filter(Message.department == department)
    if semester:   q = q.filter(Message.semester   == semester)
    if course_code: q = q.filter(Message.course_code == course_code)
    if flagged is not None: q = q.filter(Message.flagged == flagged)
    return [m.__dict__ | {"created_at": m.created_at.isoformat() + "Z"} for m in q.order_by(Message.id.desc()).limit(500).all()]
