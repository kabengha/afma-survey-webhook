import os
import json
import base64
import logging
import datetime
import hashlib

import gspread
from google.oauth2.service_account import Credentials
from flask import Flask, request, Response, jsonify

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,  
)
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --------------------------------------------------
# App & logging
# --------------------------------------------------
app = Flask(__name__)
app.logger.setLevel(logging.INFO)


# --------------------------------------------------
# Base64 helpers (Meta often uses urlsafe + sometimes missing padding)
# --------------------------------------------------
def b64decode_str(s: str) -> bytes:
    s = (s or "").strip()
    s += "=" * (-len(s) % 4)  # pad if missing
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def b64encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def flip_iv(iv: bytes) -> bytes:
    return bytes([x ^ 0xFF for x in iv])


# --------------------------------------------------
# Load RSA private key for Meta Flows (Render-safe)
# - Prefer env PRIVATE_KEY_PEM (recommended)
# - Fallback to file PRIVATE_KEY_PATH
# --------------------------------------------------
def load_private_key():
    pem_env = os.getenv("PRIVATE_KEY_PEM")
    if pem_env:
        pem_env = pem_env.strip()

        # If pasted as one line with literal \n
        if "\\n" in pem_env and "\n" not in pem_env:
            pem_env = pem_env.replace("\\n", "\n")

        # Remove wrapping quotes if present
        if (pem_env.startswith('"') and pem_env.endswith('"')) or (pem_env.startswith("'") and pem_env.endswith("'")):
            pem_env = pem_env[1:-1]

        key = load_pem_private_key(pem_env.encode("utf-8"), password=None)
        app.logger.info("✅ PRIVATE_KEY loaded from env PRIVATE_KEY_PEM (len=%s)", len(pem_env))
        return key

    path = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
    with open(path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    app.logger.info("✅ PRIVATE_KEY loaded from file: %s", path)
    return key


PRIVATE_KEY = load_private_key()

# Log a safe fingerprint of the PUBLIC key derived from private key (no secrets)
PUB_PEM = PRIVATE_KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
PUB_FP = hashlib.sha256(PUB_PEM).hexdigest()[:16]
app.logger.info("🔑 PublicKey fingerprint (sha256 first16) = %s", PUB_FP)


# --------------------------------------------------
# Google Sheets helpers
# --------------------------------------------------
def get_gsheet_client():
    sa_json = os.getenv("GOOGLE_SA_JSON")
    if not sa_json:
        raise RuntimeError("Missing env GOOGLE_SA_JSON")

    creds_info = json.loads(sa_json)
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(creds_info, scopes=scopes)
    return gspread.authorize(creds)


def append_response_row(row: list):
    sheet_id = os.getenv("GSHEET_ID")
    tab_name = os.getenv("GSHEET_TAB", "responses")
    if not sheet_id:
        raise RuntimeError("Missing env GSHEET_ID")

    gc = get_gsheet_client()
    sh = gc.open_by_key(sheet_id)
    ws = sh.worksheet(tab_name)

    app.logger.info("✅ Appending to sheet_id=%s tab=%s", sheet_id, tab_name)
    ws.append_row(row, value_input_option="RAW")


# --------------------------------------------------
# Crypto helpers (Meta Flows)
# --------------------------------------------------
def rsa_decrypt_aes_key(encrypted_aes_key_b64: str) -> bytes:
    encrypted_aes_key = b64decode_str(encrypted_aes_key_b64)
    return PRIVATE_KEY.decrypt(
        encrypted_aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_gcm_decrypt(ciphertext_plus_tag: bytes, aes_key: bytes, iv: bytes) -> bytes:
    if len(ciphertext_plus_tag) < 16:
        raise ValueError("Invalid encrypted_flow_data (too short)")
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
    return ct + encryptor.tag


# --------------------------------------------------
# Health endpoints
# --------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok"}), 200


@app.route("/api/survey/webhook", methods=["GET"])
def flow_health():
    return jsonify({"status": "ok"}), 200


# --------------------------------------------------
# Meta Flow endpoint (PING / INIT / DATA_EXCHANGE)
# --------------------------------------------------
@app.route("/api/survey/webhook", methods=["POST"])
def flow_endpoint():
    body = request.get_json(silent=True) or {}

    try:
        # required fields
        for k in ("encrypted_flow_data", "encrypted_aes_key", "initial_vector"):
            if k not in body:
                return jsonify({"error": f"Missing field: {k}"}), 400

        app.logger.info(
            "Flow HIT fp=%s sizes data=%s aes=%s iv=%s",
            PUB_FP,
            len(body.get("encrypted_flow_data", "")),
            len(body.get("encrypted_aes_key", "")),
            len(body.get("initial_vector", "")),
        )

        encrypted_flow_data = b64decode_str(body["encrypted_flow_data"])
        iv = b64decode_str(body["initial_vector"])

        # RSA decrypt AES key
        aes_key = rsa_decrypt_aes_key(body["encrypted_aes_key"])
        app.logger.info("✅ RSA ok fp=%s aes_key_len=%s", PUB_FP, len(aes_key))

        # AES-GCM decrypt payload
        plaintext = aes_gcm_decrypt(encrypted_flow_data, aes_key, iv)
        incoming = json.loads(plaintext.decode("utf-8"))
        app.logger.info("Incoming Flow payload: %s", incoming)

        action = (incoming.get("action") or "").upper()
        flow_token = incoming.get("flow_token")

        # Build response payload (plaintext JSON)
        if action == "PING":
            response_payload = {"version": "3.0", "data": {"status": "active"}}

        elif action in ("INIT", "DATA_EXCHANGE"):
            segment = None
            if flow_token and "|" in flow_token:
                segment = flow_token.split("|", 1)[0].strip()

            response_payload = {
                "version": "3.0",
                "screen": "QUESTION_ONE",
                "data": {
                    "campaign_id": os.getenv("DEFAULT_CAMPAIGN_ID", "SURVEY_2026_01_22"),
                    "segment": segment or os.getenv("DEFAULT_SEGMENT", "SEG_DEFAULT"),
                },
            }

        else:
            # safe fallback
            response_payload = {"version": "3.0", "data": {"status": "active"}}

        # Encrypt response with flipped IV
        out_iv = flip_iv(iv)
        encrypted_response = aes_gcm_encrypt(
            json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
            aes_key,
            out_iv,
        )

        # Meta expects base64(ciphertext||tag) in plain text
        return Response(
            b64encode_bytes(encrypted_response),
            status=200,
            mimetype="text/plain",
        )

    except Exception as e:
        app.logger.exception("❌ Flow endpoint error fp=%s", PUB_FP)
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# WhatsApp webhook verification (Meta subscribe)
# --------------------------------------------------
@app.route("/webhook/whatsapp", methods=["GET"])
def whatsapp_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    VERIFY_TOKEN = os.getenv("WH_VERIFY_TOKEN", "my_verify_token")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200, mimetype="text/plain")

    return Response("Forbidden", status=403)


# --------------------------------------------------
# WhatsApp messages webhook (Flow answers) -> Google Sheets
# --------------------------------------------------
@app.route("/webhook/whatsapp", methods=["POST"])
def whatsapp_messages():
    payload = request.get_json(silent=True) or {}

    app.logger.info("✅ Incoming WhatsApp webhook HIT")
    app.logger.info("Incoming WhatsApp webhook payload: %s", payload)

    try:
        entries = payload.get("entry") or []
        if not entries:
            return jsonify({"status": "ignored_no_entry"}), 200

        saved_count = 0

        for entry in entries:
            changes = entry.get("changes") or []
            for change in changes:
                value = change.get("value") or {}
                messages = value.get("messages") or []
                if not messages:
                    continue

                for msg in messages:
                    from_number = msg.get("from", "")
                    ts = datetime.datetime.utcnow().isoformat()

                    interactive = msg.get("interactive") or {}
                    nfm_reply = interactive.get("nfm_reply")
                    if not nfm_reply:
                        continue  # not a Flow reply

                    response_json_str = nfm_reply.get("response_json") or "{}"
                    try:
                        response_data = json.loads(response_json_str)
                    except Exception:
                        response_data = {"_raw": response_json_str}

                    data_obj = response_data.get("data", {}) if isinstance(response_data, dict) else {}

                    campaign_id = response_data.get("campaign_id") or data_obj.get("campaign_id", "")
                    segment = response_data.get("segment") or data_obj.get("segment", "")

                    q1 = response_data.get("q1") or data_obj.get("q1", "")
                    q2 = response_data.get("q2") or data_obj.get("q2", "")
                    q3 = response_data.get("q3") or data_obj.get("q3", "")

                    raw_json = json.dumps(response_data, ensure_ascii=False)

                    append_response_row([ts, from_number, campaign_id, segment, q1, q2, q3, raw_json])
                    saved_count += 1

        return jsonify({"status": "ok", "saved": saved_count}), 200

    except Exception as e:
        app.logger.exception("❌ WhatsApp webhook error")
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Local run
# --------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
