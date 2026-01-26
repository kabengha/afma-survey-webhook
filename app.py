import base64
import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

# Charger la PRIVATE KEY
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():

    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    # 👉 Réponse Flow OBLIGATOIRE
    response_payload = {
        "status": "ok"
    }

    encrypted = private_key.encrypt(
        json.dumps(response_payload).encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_base64 = base64.b64encode(encrypted).decode()

    return jsonify({
        "encrypted_response": encrypted_base64
    }), 200
