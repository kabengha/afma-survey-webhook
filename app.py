import os
import json
import base64
import logging
import datetime

import gspread
from google.oauth2.service_account import Credentials
from flask import Flask, request, Response, jsonify

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --------------------------------------------------
# App & logging
# --------------------------------------------------
app = Flask(__name__)
app.logger.setLevel(logging.INFO)


# --------------------------------------------------
# RSA private key (Meta Flow)
# --------------------------------------------------
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = load_pem_private_key(f.read(), password=None)


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
    app.logger.info("Appending to sheet=%s tab=%s", sheet_id, tab_name)
    ws.append_row(row, value_input_option="RAW")


# --------------------------------------------------
# Crypto helpers
# --------------------------------------------------
def b64decode_str(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def b64encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def flip_iv(iv: bytes) -> bytes:
    # XOR 0xFF sur chaque byte
    return bytes([x ^ 0xFF for x in iv])


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
        raise ValueError("Invalid encrypted_flow_data")

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
# Meta Flow endpoint (INIT / ping)
# --------------------------------------------------
@app.route("/api/survey/webhook", methods=["POST"])
def flow_endpoint():
    body = request.get_json(silent=True) or {}

    try:
        encrypted_flow_data = b64decode_str(body["encrypted_flow_data"])
        encrypted_aes_key = body["encrypted_aes_key"]
        iv = b64decode_str(body["initial_vector"])

        aes_key = rsa_decrypt_aes_key(encrypted_aes_key)
        plaintext = aes_gcm_decrypt(encrypted_flow_data, aes_key, iv)
        incoming = json.loads(plaintext.decode("utf-8"))

        app.logger.info("Incoming Flow payload: %s", incoming)

        action = (incoming.get("action") or "").upper()
        flow_token = incoming.get("flow_token")

        # -------- PING --------
        if action == "PING":
            response_payload = {
                "version": "3.0",
                "data": {"status": "active"},
            }

        # -------- INIT / DATA_EXCHANGE --------
        elif action in ("INIT", "DATA_EXCHANGE"):
            segment = None
            if flow_token and "|" in flow_token:
                segment = flow_token.split("|", 1)[0].strip()

            response_payload = {
                "version": "3.0",
                "screen": "QUESTION_ONE",
                "data": {
                    "campaign_id": os.getenv(
                        "DEFAULT_CAMPAIGN_ID", "SURVEY_2026_01_22"
                    ),
                    "segment": segment
                    or os.getenv("DEFAULT_SEGMENT", "SEG_DEFAULT"),
                },
            }

        # -------- SAFE FALLBACK --------
        else:
            response_payload = {
                "version": "3.0",
                "data": {"status": "active"},
            }

        out_iv = flip_iv(iv)
        encrypted_response = aes_gcm_encrypt(
            json.dumps(response_payload, separators=(",", ":")).encode("utf-8"),
            aes_key,
            out_iv,
        )

        return Response(
            b64encode_bytes(encrypted_response),
            status=200,
            mimetype="text/plain",
        )

    except Exception as e:
        app.logger.exception("Flow endpoint error")
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# WhatsApp webhook verification
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
# WhatsApp messages webhook (Flow responses)
# --------------------------------------------------
@app.route("/webhook/whatsapp", methods=["POST"])
def whatsapp_messages():
    payload = request.get_json(silent=True) or {}
    app.logger.info("Incoming WhatsApp webhook")

    try:
        entries = payload.get("entry") or []
        for entry in entries:
            changes = entry.get("changes") or []
            for change in changes:
                value = change.get("value") or {}
                messages = value.get("messages") or []

                for msg in messages:
                    interactive = msg.get("interactive") or {}
                    nfm_reply = interactive.get("nfm_reply")
                    if not nfm_reply:
                        continue

                    from_number = msg.get("from", "")
                    ts = datetime.datetime.utcnow().isoformat()

                    response_json_str = nfm_reply.get("response_json") or "{}"
                    try:
                        response_data = json.loads(response_json_str)
                    except Exception:
                        response_data = {"_raw": response_json_str}

                    campaign_id = (
                        response_data.get("campaign_id")
                        or response_data.get("data", {}).get("campaign_id", "")
                    )
                    segment = (
                        response_data.get("segment")
                        or response_data.get("data", {}).get("segment", "")
                    )

                    q1 = response_data.get("q1") or response_data.get("data", {}).get(
                        "q1", ""
                    )
                    q2 = response_data.get("q2") or response_data.get("data", {}).get(
                        "q2", ""
                    )
                    q3 = response_data.get("q3") or response_data.get("data", {}).get(
                        "q3", ""
                    )

                    raw_json = json.dumps(response_data, ensure_ascii=False)

                    append_response_row(
                        [ts, from_number, campaign_id, segment, q1, q2, q3, raw_json]
                    )

        return jsonify({"status": "saved"}), 200

    except Exception as e:
        app.logger.exception("WhatsApp webhook error")
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------
# Local run (Render uses gunicorn)
# --------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
