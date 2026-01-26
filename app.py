import os
import json
import base64
from flask import Flask, request, Response, jsonify

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# 🔐 RSA private key (sert uniquement à déchiffrer la clé AES envoyée par Meta)
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = load_pem_private_key(f.read(), password=None)


def b64decode_str(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def b64encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def flip_iv(iv: bytes) -> bytes:
    return bytes([x ^ 0xFF for x in iv])


def rsa_decrypt_aes_key(encrypted_aes_key_b64: str) -> bytes:
    encrypted_aes_key = b64decode_str(encrypted_aes_key_b64)
    aes_key = PRIVATE_KEY.decrypt(
        encrypted_aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


def aes_gcm_decrypt(ciphertext_plus_tag: bytes, aes_key: bytes, iv: bytes) -> bytes:
    if len(ciphertext_plus_tag) < 16:
        raise ValueError("Invalid encrypted_flow_data: too short")

    ct = ciphertext_plus_tag[:-16]
    tag = ciphertext_plus_tag[-16:]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
    ).decryptor()

    return decryptor.update(ct) + decryptor.finalize()


def aes_gcm_encrypt(plaintext: bytes, aes_key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
    ).encryptor()

    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct + encryptor.tag  # ciphertext || tag(16)


@app.route("/api/survey/webhook", methods=["GET"])
def health_get():
    return jsonify({"status": "ok"}), 200


@app.route("/api/survey/webhook", methods=["POST"])
def flow_endpoint():
    body = request.get_json(silent=True) or {}

    try:
        # Champs obligatoires envoyés par Meta Flows
        encrypted_flow_data = b64decode_str(body["encrypted_flow_data"])
        encrypted_aes_key_b64 = body["encrypted_aes_key"]
        iv = b64decode_str(body["initial_vector"])

        # 1) Déchiffrer la clé AES (RSA private key)
        aes_key = rsa_decrypt_aes_key(encrypted_aes_key_b64)

        # 2) Déchiffrer le payload entrant (AES-GCM)
        plaintext_bytes = aes_gcm_decrypt(encrypted_flow_data, aes_key, iv)
        incoming = json.loads(plaintext_bytes.decode("utf-8"))

        # (Optionnel) log debug
        app.logger.info("Incoming flow payload: %s", incoming)

        # ✅ Réponse EXACTE attendue par Meta pour passer l’état
        action = incoming.get("action")
        screen = incoming.get("screen")
        flow_token = incoming.get("flow_token")
        
        # 1) Status check
        if action == "ping":
            response_payload = {"data": {"status": "active"}}
        
        # 2) Request data on first screen
        elif action == "data_exchange" and screen == "QUESTION_ONE":
            # segment: soit depuis flow_token (recommandé), soit fallback
            # Exemple flow_token = "SEG_CASA_RABAT|random123"
            segment = None
            if flow_token and "|" in flow_token:
                segment = flow_token.split("|", 1)[0].strip()
        
            response_payload = {
                "screen": "QUESTION_ONE",
                "data": {
                    "campaign_id": os.getenv("DEFAULT_CAMPAIGN_ID", "SURVEY_2026_01_22"),
                    "segment": segment or os.getenv("DEFAULT_SEGMENT", "SEG_DEFAULT"),
                },
            }
        
        # 3) Default safe response
        else:
            response_payload = {"data": {"status": "active"}}


        # 3) Chiffrer la réponse (AES-GCM) avec IV “flippé”
        out_iv = flip_iv(iv)
        encrypted_response_bytes = aes_gcm_encrypt(
            json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
            aes_key,
            out_iv,
        )

        encrypted_response_b64 = b64encode_bytes(encrypted_response_bytes)

        # ⚠️ IMPORTANT: body = Base64 string (text/plain), pas JSON
        return Response(encrypted_response_b64, status=200, mimetype="text/plain")

    except KeyError as e:
        # Meta envoie toujours les 3 champs en POST, mais au cas où
        return jsonify({"error": "missing_field", "details": str(e)}), 400
    except Exception as e:
        # Si Meta voit 500, regarde Render logs -> cette "details"
        app.logger.exception("Flow endpoint error")
        return jsonify({"error": "internal_error", "details": str(e)}), 500
