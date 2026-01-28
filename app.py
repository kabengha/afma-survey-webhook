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

# ----------------------------
# Google Sheets
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

def b64d(s: str) -> bytes:
    s = (s or "").strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def load_private_key():
    """
    Use ONE:
      - FLOW_PRIVATE_KEY_PEM  (recommended)
      - FLOW_PRIVATE_KEY_FILE (path, default private_key.pem)
    """
    passphrase = os.getenv("FLOW_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode("utf-8") if passphrase else None

    pem_env = os.getenv("FLOW_PRIVATE_KEY_PEM")
    if pem_env:
        return load_pem_private_key(pem_env.encode("utf-8"), password=password)

    key_file = os.getenv("FLOW_PRIVATE_KEY_FILE", "private_key.pem")
    if not os.path.exists(key_file):
        raise RuntimeError(f"Private key file not found: {key_file}")

    with open(key_file, "rb") as f:
        pem_bytes = f.read()

    return load_pem_private_key(pem_bytes, password=password)

def decrypt_flow(body: dict):
    """
    Meta sends:
      - encrypted_aes_key (base64) : RSA-OAEP encrypted AES key
      - initial_vector (base64)   : iv/nonce
      - encrypted_flow_data (base64): AES-GCM ciphertext||tag
    """
    enc_key_b64 = body.get("encrypted_aes_key")
    iv_b64 = body.get("initial_vector")
    data_b64 = body.get("encrypted_flow_data")
    if not (enc_key_b64 and iv_b64 and data_b64):
        raise RuntimeError("Missing encrypted_aes_key / initial_vector / encrypted_flow_data")

    private_key = load_private_key()

    aes_key = private_key.decrypt(
        b64d(enc_key_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    iv = b64d(iv_b64)
    ciphertext_tag = b64d(data_b64)

    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_tag, None)

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        payload = {"_decrypted_text": plaintext.decode("utf-8", errors="replace")}

    return payload, aes_key, iv

def encrypt_response(aes_key: bytes, iv: bytes, obj: dict) -> str:
    """
    Meta expects: base64( AES-GCM(plaintext_json) ) as RAW TEXT response.
    """
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    ciphertext_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return b64e(ciphertext_tag)

# ----------------------------
# Routes
# ----------------------------
@app.post("/api/survey/webhook")
@app.post("/webhook")
@app.post("/webhook/whatsapp")
def webhook():
    body = request.get_json(force=True, silent=False) or {}
    # On doit toujours renvoyer une réponse chiffrée si on reçoit un payload chiffré
    try:
        payload, aes_key, iv = decrypt_flow(body)

        # ping / availability check
        if payload.get("action") == "ping":
            resp = {"version": payload.get("version", "3.0"), "action": "pong"}
            return encrypt_response(aes_key, iv, resp), 200, {"Content-Type": "text/plain"}

        # ----- ici ton extraction -----
        ts = now_iso()
        phone = str(payload.get("from") or payload.get("phone") or "")
        campaign_id = payload.get("campaign_id", "")
        segment = payload.get("segment", "") or payload.get("flow_token", "")

        q1 = payload.get("q1", "")
        q2 = payload.get("q2", "")
        q3 = payload.get("q3", "")

        raw_json = json.dumps(payload, ensure_ascii=False)
        row = [ts, phone, campaign_id, segment, q1, q2, q3, raw_json]
        append_row_to_sheet(row)

        resp = {"ok": True}
        return encrypt_response(aes_key, iv, resp), 200, {"Content-Type": "text/plain"}

    except Exception as e:
        # IMPORTANT: même en erreur, Meta veut souvent une réponse "valide" (sinon endpoint inactive)
        # Si on n'a pas pu déchiffrer, on répond juste OK non chiffré (au moins 200)
        print("WEBHOOK_ERROR:", str(e), flush=True)
        return "OK", 200, {"Content-Type": "text/plain"}

@app.get("/health")
@app.get("/")
def health():
    return "OK", 200
