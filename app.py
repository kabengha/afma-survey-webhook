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
        raise Exception("PRIVATE_KEY_PEM manquante dans Render")

    pem = pem.replace("\\n", "\n").strip()
    return serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None
    )

private_key = load_private_key()

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():
    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    payload = {
        "data": {
            "status": "active"
        }
    }

    encrypted = private_key.encrypt(
        json.dumps(payload, separators=(",", ":")).encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return jsonify({
        "encrypted_response": base64.b64encode(encrypted).decode()
    }), 200
