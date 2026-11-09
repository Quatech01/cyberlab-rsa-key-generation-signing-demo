import base64
import threading
import time
import urllib.request

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = FastAPI()

# Generate a 2048-bit RSA key pair at module load time so the server is ready immediately.
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()


class SignRequest(BaseModel):
    message: str


class VerifyRequest(BaseModel):
    message: str
    signature: str  # base64-encoded


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/public-key")
def public_key():
    pem = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {
        "public_key_pem": pem,
        "key_size_bits": _public_key.key_size,
        "algorithm": "RSA",
    }


@app.post("/sign")
def sign_pss(req: SignRequest):
    """Sign a message with RSA-PSS (PKCS#1 v2.1) — the secure modern scheme."""
    signature = _private_key.sign(
        req.message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return {
        "signature": base64.b64encode(signature).decode(),
        "padding": "PSS",
        "hash": "SHA-256",
    }


@app.post("/sign/pkcs1v15")
def sign_pkcs1v15(req: SignRequest):
    """Sign a message with PKCS#1 v1.5 — the older, deterministic, deprecated scheme."""
    signature = _private_key.sign(
        req.message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return {
        "signature": base64.b64encode(signature).decode(),
        "padding": "PKCS1v15",
        "hash": "SHA-256",
    }


@app.post("/verify/secure")
def verify_secure(req: VerifyRequest):
    """Cryptographically verify a signature — rejects all forgeries."""
    try:
        sig_bytes = base64.b64decode(req.signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in signature field")

    for pad in [
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        padding.PKCS1v15(),
    ]:
        try:
            _public_key.verify(sig_bytes, req.message.encode(), pad, hashes.SHA256())
            return {"valid": True, "endpoint": "secure"}
        except Exception:
            continue
    return {"valid": False, "endpoint": "secure"}


@app.post("/verify/weak")
def verify_weak(req: VerifyRequest):
    """Vulnerable: only checks that the signature field is non-empty.
    Performs no cryptographic verification — accepts any forged signature."""
    if req.signature and len(req.signature) > 0:
        return {"valid": True, "endpoint": "weak"}
    return {"valid": False, "endpoint": "weak"}


def start(port: int = 3000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)
    return server


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
