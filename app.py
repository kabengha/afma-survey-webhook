import os
import json
import base64
from datetime import datetime, timezone

from flask import Flask, request
import gspread
from google.oauth2.service_account import Credentials

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
APP_VERSION = "v2026-01-28-17-05"


# ----------------------------
# Meta requires BASE64 body
# ----------------------------
def base64_response(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


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


def b64d(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)


def decrypt_encrypted_flow_data(body: dict) -> dict:
    """
    Expect fields:
      - encrypted_aes_key (base64 RSA-OAEP encrypted AES key)
      - initial_vector (base64 IV/nonce)
      - encrypted_flow_data (base64 AES-GCM ciphertext||tag)
    """
    private_key = load_private_key()

    enc_key_b64 = body.get("encrypted_aes_key")
    iv_b64 = body.get("initial_vector")
    data_b64 = body.get("encrypted_flow_data")

    if not (enc_key_b64 and iv_b64 and data_b64):
        raise RuntimeError("Missing encrypted_aes_key / initial_vector / encrypted_flow_data")

    # RSA decrypt AES key
    enc_aes_key = b64d(enc_key_b64)
    aes_key = private_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # AES-GCM decrypt
    iv = b64d(iv_b64)
    ciphertext_and_tag = b64d(data_b64)
    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_and_tag, None)

    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return {"_decrypted_text": plaintext.decode("utf-8", errors="replace")}


def extract_payload(body: dict) -> dict:
    # If encrypted_flow_data exists → decrypt using full body
    if body.get("encrypted_flow_data") and body.get("encrypted_aes_key") and body.get("initial_vector"):
        return decrypt_encrypted_flow_data(body)

    # fallback formats
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
        if isinstance(c, dict):
            return c
    return {}


# ----------------------------
# Single handler
# ----------------------------
def handle_meta_webhook():
    body = request.get_json(force=True, silent=True) or {}
    payload = extract_payload(body)

    phone = extract_from(body)
    ts = now_iso()

    # (selon ton Flow JSON, campaign_id/segment viennent de data)
    campaign_id = payload.get("campaign_id") or dig(payload, "data", "campaign_id") or ""
    segment = payload.get("segment") or dig(payload, "data", "segment") or payload.get("flow_token", "") or ""

    q1 = payload.get("q1", "")
    q2 = payload.get("q2", "")
    q3 = payload.get("q3", "")

    raw_json = json.dumps(payload if payload else body, ensure_ascii=False)

    # ✅ Évite polluer le sheet avec ping / events
    if q1 or q2 or q3:
        row = [ts, phone, campaign_id, segment, q1, q2, q3, raw_json]
        append_row_to_sheet(row)

    # ✅ Meta expects BASE64 body
    return base64_response({"ok": True}), 200


# ----------------------------
# Routes
# ----------------------------
@app.post("/webhook")
def webhook():
    try:
        return handle_meta_webhook()
    except Exception:
        app.logger.exception("Webhook error")
        # ✅ Always BASE64, even on error
        return base64_response({"ok": False}), 200


@app.post("/api/survey/webhook")
def webhook_api_survey():
    return webhook()


@app.post("/webhook/whatsapp")
def webhook_whatsapp():
    return webhook()


@app.get("/health")
def health():
    return json.dumps({"ok": True, "version": APP_VERSION}), 200


@app.get("/")
def root():
    return "OK", 200
