import os
import json
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

# Charge la clé privée (celle qui correspond à la public key upload sur Meta)
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")

with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():
    # Health check simple
    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    # ✅ Payload EXACT attendu par Meta pour l’étape "État"
    response_payload = {"data": {"status": "active"}}

    # Chiffre la réponse en RSA OAEP SHA256 puis encode en base64
    encrypted = private_key.encrypt(
        json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_base64 = base64.b64encode(encrypted).decode("utf-8")

    return jsonify({"encrypted_response": encrypted_base64}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
