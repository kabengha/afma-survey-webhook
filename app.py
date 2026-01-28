import os
import json
import base64
from datetime import datetime, timezone

from flask import Flask, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

# ----------------------------
# Google Sheets client
# ----------------------------
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

# ----------------------------
# Helpers
# ----------------------------
def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def dig(d, *keys):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur

def extract_from(body: dict) -> str:
    return (
        str(dig(body, "from") or "")
        or str(dig(body, "sender") or "")
        or str(dig(body, "contact", "phone") or "")
        or str(dig(body, "message", "from") or "")
        or ""
    )

def load_private_key():
    """
    Loads private key either from:
      - FLOW_PRIVATE_KEY_PEM (env var)
      - FLOW_PRIVATE_KEY_FILE (env var path) or default 'private_key.pem'
    """
    passphrase = os.getenv("FLOW_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode("utf-8") if passphrase else None

    priv_pem_env = os.getenv("FLOW_PRIVATE_KEY_PEM")
    if priv_pem_env:
        return load_pem_private_key(priv_pem_env.encode("utf-8"), password=password)

    key_file = os.getenv("FLOW_PRIVATE_KEY_FILE", "private_key.pem")
    if not os.path.exists(key_file):
        raise RuntimeError(f"Private key file not found: {key_file}")

    with open(key_file, "rb") as f:
        pem_bytes = f.read()

    return load_pem_private_key(pem_bytes, password=password)

def decrypt_encrypted_flow_data(enc_b64: str) -> dict:
    """
    Tries RSA OAEP decrypt of encrypted_flow_data (base64).
    If your encrypted_flow_data format differs, we will adjust after seeing the error.
    """
    private_key = load_private_key()
    ciphertext = base64.b64decode(enc_b64)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return json.loads(plaintext.decode("utf-8"))

def extract_payload(body: dict) -> dict:
    # 1) If encrypted_flow_data exists, decrypt it
    enc = body.get("encrypted_flow_data") \
          or dig(body, "payload", "encrypted_flow_data") \
          or dig(body, "data", "encrypted_flow_data")

    if enc:
        try:
            clear = decrypt_encrypted_flow_data(enc)
            return clear if isinstance(clear, dict) else {"_decrypted": clear}
        except Exception as e:
            # keep encrypted in raw_json and raise (so you see the real error)
            raise RuntimeError(f"Failed to decrypt encrypted_flow_data: {e}")

    # 2) Fallback: non-encrypted formats
    candidates = [
        body,
        dig(body, "payload"),
        dig(body, "flow"),
        dig(body, "data"),
        dig(body, "content"),
        dig(body, "content", "data"),
        dig(body, "message"),
        dig(body, "message", "content"),
        dig(body, "message", "content", "data"),
        dig(body, "entry", 0, "changes", 0, "value"),
    ]
    for c in candidates:
        if isinstance(c, dict) and any(k in c for k in ["q1", "q2", "q3", "campaign_id", "segment", "flow_token"]):
            return c

    return {}

@app.post("/webhook")
def webhook():
    try:
        body = request.get_json(force=True, silent=False) or {}

        # Debug: show if encrypted payload
        if isinstance(body, dict) and "encrypted_flow_data" in body:
            print("INCOMING encrypted_flow_data detected", flush=True)

        payload = extract_payload(body)

        phone = extract_from(body)
        ts = now_iso()

        campaign_id = payload.get("campaign_id", "")
        segment = payload.get("segment", "") or payload.get("flow_token", "")

        q1 = payload.get("q1", "")
        q2 = payload.get("q2", "")
        q3 = payload.get("q3", "")

        raw_json = json.dumps(payload if payload else body, ensure_ascii=False)

        row = [ts, phone, campaign_id, segment, q1, q2, q3, raw_json]
        append_row_to_sheet(row)

        return jsonify({"ok": True}), 200

    except Exception as e:
        app.logger.exception("Webhook error")
        return jsonify({"ok": False, "error": str(e)}), 500

# Aliases to match callers
@app.post("/webhook/whatsapp")
def webhook_whatsapp():
    return webhook()

@app.post("/api/survey/webhook")
def webhook_api_survey():
    return webhook()

@app.get("/health")
def health():
    return "OK", 200
