import os
import json
import base64
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response

import gspread
from google.oauth2.service_account import Credentials

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)

# ============================================================
# Google Sheets
# ============================================================

def get_gspread_client():
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    sa_json = os.getenv("GOOGLE_SA_JSON")
    sa_file = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

    if sa_json:
        info = json.loads(sa_json)
        creds = Credentials.from_service_account_info(info, scopes=scopes)
    elif sa_file:
        creds = Credentials.from_service_account_file(sa_file, scopes=scopes)
    else:
        raise RuntimeError("Missing GOOGLE_SA_JSON or GOOGLE_SERVICE_ACCOUNT_FILE")

    return gspread.authorize(creds)


def append_row_to_sheet(row):
    sheet_id = os.getenv("GSHEET_ID")
    tab_name = os.getenv("GSHEET_TAB", "Sheet1")

    if not sheet_id:
        raise RuntimeError("Missing GSHEET_ID env var")

    gc = get_gspread_client()
    sh = gc.open_by_key(sheet_id)
    ws = sh.worksheet(tab_name)
    ws.append_row(row, value_input_option="RAW")


# ============================================================
# Utils
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def dig(d, *keys):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, list) and isinstance(k, int) and 0 <= k < len(cur):
            cur = cur[k]
        else:
            return None
    return cur


def extract_phone_from_anywhere(obj: dict) -> str:
    """
    NB: Dans le payload Flow chiffré, le phone n’est pas toujours présent.
    Donc on essaie, sinon vide => tu relies via flow_token.
    """
    candidates = [
        dig(obj, "from"),
        dig(obj, "sender"),
        dig(obj, "contact", "phone"),
        dig(obj, "message", "from"),
        dig(obj, "contacts", 0, "wa_id"),
        dig(obj, "messages", 0, "from"),
        dig(obj, "entry", 0, "changes", 0, "value", "messages", 0, "from"),
        dig(obj, "entry", 0, "changes", 0, "value", "contacts", 0, "wa_id"),
    ]
    for c in candidates:
        if c:
            return str(c)
    return ""


def b64d(s: str) -> bytes:
    s = (s or "").strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


# ============================================================
# RSA key loading
# ============================================================

def load_private_key():
    """
    Charge la clé privée depuis:
      - FLOW_PRIVATE_KEY_PEM (env var)   [recommandé Render]
      - ou FLOW_PRIVATE_KEY_FILE (path)
    Si Render stocke la PEM en une ligne avec "\\n", on convertit.
    """
    passphrase = os.getenv("FLOW_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode("utf-8") if passphrase else None

    priv_pem_env = os.getenv("FLOW_PRIVATE_KEY_PEM")
    if priv_pem_env:
        pem = priv_pem_env.replace("\\n", "\n").encode("utf-8")
        return load_pem_private_key(pem, password=password)

    key_file = os.getenv("FLOW_PRIVATE_KEY_FILE", "private_key.pem")
    if not os.path.exists(key_file):
        raise RuntimeError(f"Private key file not found: {key_file}")

    with open(key_file, "rb") as f:
        pem_bytes = f.read()

    return load_pem_private_key(pem_bytes, password=password)


PRIVATE_KEY = None


@app.before_request
def _init_key_once():
    global PRIVATE_KEY
    if PRIVATE_KEY is None:
        PRIVATE_KEY = load_private_key()


# ============================================================
# Meta Flows Crypto
# ============================================================

def decrypt_flow_payload(body: dict):
    """
    Attend les champs top-level:
      - encrypted_flow_data (base64)
      - encrypted_aes_key (base64)
      - initial_vector (base64)

    Retourne: (req_dict, aes_key_bytes, iv_bytes)
    """
    enc_key_b64 = body.get("encrypted_aes_key")
    iv_b64 = body.get("initial_vector")
    data_b64 = body.get("encrypted_flow_data")

    if not (enc_key_b64 and iv_b64 and data_b64):
        raise RuntimeError("Missing encrypted_aes_key / initial_vector / encrypted_flow_data")

    # RSA-OAEP decrypt AES key
    enc_aes_key = b64d(enc_key_b64)
    aes_key = PRIVATE_KEY.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # AES-GCM decrypt payload (ciphertext||tag)
    iv = b64d(iv_b64)
    ciphertext_and_tag = b64d(data_b64)

    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_and_tag, None)
    req = json.loads(plaintext.decode("utf-8"))
    return req, aes_key, iv


def invert_iv(iv: bytes) -> bytes:
    # IV réponse = bitwise NOT de l’IV reçu
    return bytes((b ^ 0xFF) for b in iv)


def encrypt_flow_response(resp_obj: dict, aes_key: bytes, req_iv: bytes) -> str:
    resp_iv = invert_iv(req_iv)
    resp_bytes = json.dumps(resp_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = AESGCM(aes_key).encrypt(resp_iv, resp_bytes, None)  # ciphertext||tag
    return b64e(ct)


# ============================================================
# Routes
# ============================================================

@app.get("/")
def root():
    return "OK", 200


@app.get("/health")
def health():
    return "OK", 200


# ------------------------------------------------------------
# Encrypted WhatsApp Flows endpoint
# ------------------------------------------------------------
@app.post("/flow")
def flow_endpoint():
    """
    IMPORTANT:
    - La réponse DOIT être une STRING base64 chiffrée (pas JSON)
    - Content-Type text/plain
    - IV réponse = inverted IV reçu
    """
    try:
        body = request.get_json(force=True, silent=False) or {}
        app.logger.info(f"[FLOW] RAW keys={list(body.keys()) if isinstance(body, dict) else type(body)}")

        req, aes_key, iv = decrypt_flow_payload(body)

        action = req.get("action")
        version = req.get("version", "3.0")
        app.logger.info(f"[FLOW] DECRYPTED action={action} keys={list(req.keys())}")

        # A) PING
        if action == "ping":
            resp_obj = {"version": version, "data": {"status": "active"}}
            encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
            return Response(encrypted, status=200, mimetype="text/plain")

        # B) SUBMIT / DATA EXCHANGE
        data = req.get("data") or {}
        flow_token = req.get("flow_token", "") or req.get("token", "")

        # Champs réponses (adapte si tes keys sont différentes)
        q1 = data.get("q1", "") or data.get("Q1", "") or ""
        q2 = data.get("q2", "") or data.get("Q2", "") or ""
        q3 = data.get("q3", "") or data.get("Q3", "") or ""

        campaign_id = data.get("campaign_id", "") or ""
        segment = data.get("segment", "") or ""

        phone = extract_phone_from_anywhere(req)

        ts = now_iso()
        raw_json = json.dumps(req, ensure_ascii=False)

        # IMPORTANT: on ne sauvegarde pas les pings, seulement les réponses user
        row = [ts, phone, flow_token, campaign_id, segment, q1, q2, q3, raw_json]
        append_row_to_sheet(row)

        # ACK chiffré
        resp_obj = {"version": version, "data": {"ok": True}}
        encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
        return Response(encrypted, status=200, mimetype="text/plain")

    except Exception:
        app.logger.exception("[FLOW] Error")
        # Si decrypt fail, ne surtout pas renvoyer une réponse en clair 200,
        # sinon Meta dit "Impossible de décrypter la réponse"
        return Response("ERROR", status=400, mimetype="text/plain")


# ------------------------------------------------------------
# ALIASES pour ton URL Meta actuelle
# Meta = https://afma-survey-webhook.onrender.com/api/survey/webhook
# ------------------------------------------------------------
@app.post("/api/survey/webhook")
@app.post("/webhook/whatsapp")
@app.post("/webhook/flow")
def flow_alias():
    return flow_endpoint()


# ------------------------------------------------------------
# Classic WhatsApp webhook (optionnel)
# ------------------------------------------------------------
@app.post("/webhook")
def webhook():
    try:
        body = request.get_json(force=True, silent=False) or {}
        phone = extract_phone_from_anywhere(body)
        ts = now_iso()
        raw_json = json.dumps(body, ensure_ascii=False)

        # Log minimal
        row = [ts, phone, "", "", "", "", "", "", raw_json]
        append_row_to_sheet(row)

        return jsonify({"ok": True}), 200

    except Exception as e:
        app.logger.exception("[WEBHOOK] Error")
        return jsonify({"ok": False, "error": str(e)}), 200


@app.get("/webhook")
def webhook_get():
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
