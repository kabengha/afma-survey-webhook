import os
import json
import base64
from flask import Flask, request, Response, jsonify

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


app = Flask(__name__)

# --- Load RSA private key (used ONLY to decrypt the AES key sent by Meta) ---
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")

with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = load_pem_private_key(f.read(), password=None)


def b64decode_str(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def b64encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def flip_iv(iv: bytes) -> bytes:
    # XOR each byte with 0xFF
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
    # Meta concatenates: ciphertext || tag(16 bytes)
    if len(ciphertext_plus_tag) < 16:
        raise ValueError("Invalid encrypted_flow_data: too short")

    ct = ciphertext_plus_tag[:-16]
    tag = ciphertext_plus_tag[-16:]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
    ).decryptor()

    plaintext = decryptor.update(ct) + decryptor.finalize()
    return plaintext


def aes_gcm_encrypt(plaintext: bytes, aes_key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
    ).encryptor()

    ct = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return ct + tag  # ciphertext || tag


@app.route("/api/survey/webhook", methods=["GET"])
def health_get():
    # just to check your server is alive
    return jsonify({"status": "ok"}), 200


@app.route("/api/survey/webhook", methods=["POST"])
def flow_endpoint():
    """
    Expected Meta payload keys (Flows):
      - encrypted_flow_data (base64)
      - encrypted_aes_key (base64)
      - initial_vector (base64)

    Response: MUST be base64 text/plain (NOT JSON)
    """
    body = request.get_json(silent=True) or {}

    # Defensive checks
    for k in ("encrypted_flow_data", "encrypted_aes_key", "initial_vector"):
        if k not in body:
            return jsonify({"error": f"Missing field: {k}"}), 400

    try:
        encrypted_flow_data = b64decode_str(body["encrypted_flow_data"])
        encrypted_aes_key_b64 = body["encrypted_aes_key"]
        iv = b64decode_str(body["initial_vector"])

        # 1) decrypt AES key with RSA private key
        aes_key = rsa_decrypt_aes_key(encrypted_aes_key_b64)

        # 2) decrypt request payload with AES-GCM
        plaintext_bytes = aes_gcm_decrypt(encrypted_flow_data, aes_key, iv)
        incoming = json.loads(plaintext_bytes.decode("utf-8"))

        # --- TODO: here you handle the flow request normally ---
        # For now we reply minimal "ok" (works for status check)
        response_payload = {}

        # 3) encrypt response with AES-GCM using flipped IV
        out_iv = flip_iv(iv)
        encrypted_response_bytes = aes_gcm_encrypt(
            json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
            aes_key,
            out_iv,
        )

        encrypted_response_b64 = b64encode_bytes(encrypted_response_bytes)

        # IMPORTANT: response body must be Base64 STRING as text/plain
        return Response(encrypted_response_b64, status=200, mimetype="text/plain")

    except Exception as e:
        # Render logs will show the real error
        return jsonify({"error": "internal_error", "details": str(e)}), 500
