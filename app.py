import os
import json
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

def load_private_key():
    pem = os.getenv("PRIVATE_KEY_PEM")
    if not pem:
        # fallback si tu veux garder le fichier local
        path = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
        with open(path, "rb") as f:
            pem_bytes = f.read()
    else:
        pem_bytes = pem.encode("utf-8")

    return serialization.load_pem_private_key(pem_bytes, password=None)

private_key = load_private_key()

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():
    # Health check
    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    # ✅ EXACT attendu par Meta
    response_payload = {"data": {"status": "active"}}

    encrypted = private_key.encrypt(
        json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
    return jsonify({"encrypted_response": encrypted_b64}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
