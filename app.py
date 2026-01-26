import base64
import json
from flask import Flask, request, jsonify, Response
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

# Charger la clé privée (le fichier private_key.pem doit être à la racine)
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():

    # 🔹 Vérification de disponibilité (Meta l’utilise)
    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    # 🔹 Réponse OBLIGATOIRE pour WhatsApp Flows
    response_payload = {
        "status": "ok"
    }

    # 🔐 Chiffrement avec la clé privée
    encrypted = private_key.encrypt(
        json.dumps(response_payload).encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 🔹 Encodage Base64 (OBLIGATOIRE)
    encrypted_base64 = base64.b64encode(encrypted).decode("utf-8")

    # ⚠️ IMPORTANT : PAS de jsonify ici
    return Response(
        json.dumps({
            "encrypted_response": encrypted_base64
        }),
        status=200,
        mimetype="application/json"
    )

if __name__ == "__main__":
    app.run()
