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

import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# =========================
# Utils
# =========================
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

def b64d(s: str) -> bytes:
    s = (s or "").strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

# =========================
# Google Sheets (cache pour vitesse)
# =========================
_GC = None
_WS = None

def get_gspread_client():
    global _GC
    if _GC is not None:
        return _GC

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

    _GC = gspread.authorize(creds)
    return _GC

def get_worksheet():
    global _WS
    if _WS is not None:
        return _WS

    sheet_id = os.getenv("GSHEET_ID")
    tab_name = os.getenv("GSHEET_TAB", "Sheet1")
    if not sheet_id:
        raise RuntimeError("Missing GSHEET_ID env var")

    gc = get_gspread_client()
    sh = gc.open_by_key(sheet_id)
    _WS = sh.worksheet(tab_name)
    return _WS

def append_row_to_sheet(row):
    ws = get_worksheet()
    ws.append_row(row, value_input_option="RAW")

# =========================
# Meta Flows - Keys
# =========================
FLOW_REQUIRED_KEYS = {"encrypted_flow_data", "encrypted_aes_key", "initial_vector"}

def _load_one_key_from_pem(pem_str: str):
    passphrase = os.getenv("FLOW_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode("utf-8") if passphrase else None
    pem_bytes = pem_str.replace("\\n", "\n").encode("utf-8")
    return load_pem_private_key(pem_bytes, password=password)

def load_private_keys():
    keys = []
    for i in range(1, 6):
        pem = os.getenv(f"FLOW_PRIVATE_KEY_PEM_{i}")
        if pem:
            keys.append(_load_one_key_from_pem(pem))

    pem_single = os.getenv("FLOW_PRIVATE_KEY_PEM")
    if pem_single:
        keys.append(_load_one_key_from_pem(pem_single))

    if not keys:
        raise RuntimeError("No private keys found. Set FLOW_PRIVATE_KEY_PEM or FLOW_PRIVATE_KEY_PEM_1")
    return keys

PRIVATE_KEYS = load_private_keys()
print(f"[BOOT] Loaded {len(PRIVATE_KEYS)} private key(s)", flush=True)

def invert_iv(iv: bytes) -> bytes:
    return bytes((b ^ 0xFF) for b in iv)

def encrypt_flow_response(resp_obj: dict, aes_key: bytes, req_iv: bytes) -> str:
    # Meta flows: IV réponse = inversion de l'IV request
    resp_iv = invert_iv(req_iv)
    resp_bytes = json.dumps(resp_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = AESGCM(aes_key).encrypt(resp_iv, resp_bytes, None)
    return b64e(ct)

def decrypt_flow_payload_try_all_keys(body: dict):
    enc_aes_key = b64d(body["encrypted_aes_key"])
    iv = b64d(body["initial_vector"])
    ciphertext_and_tag = b64d(body["encrypted_flow_data"])

    last_err = None
    for idx, key in enumerate(PRIVATE_KEYS, start=1):
        try:
            aes_key = key.decrypt(
                enc_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_and_tag, None)
            req = json.loads(plaintext.decode("utf-8"))
            return req, aes_key, iv, idx
        except Exception as e:
            last_err = e

    raise ValueError(f"Decryption failed for all keys: {last_err}")

# =========================
# Routes basics
# =========================
@app.get("/")
def root():
    return "OK", 200

@app.get("/health")
def health():
    return "OK", 200

# Alias GET (si Meta fait un GET)
@app.get("/api/survey/webhook")
def flow_alias_get():
    return "OK", 200

# =========================
# FLOW endpoint (rapide, sans Google Sheets)
# =========================
@app.post("/flow")
def flow_endpoint():
    print("[FLOW] PATH=", request.path, flush=True)
    print("[FLOW] UA=", request.headers.get("User-Agent", ""), flush=True)

    try:
        body = request.get_json(force=True, silent=False) or {}
        print("[FLOW] RAW keys=", list(body.keys()) if isinstance(body, dict) else str(type(body)), flush=True)

        if not isinstance(body, dict) or not FLOW_REQUIRED_KEYS.issubset(set(body.keys())):
            # IMPORTANT: répondre 200 OK pour éviter des retries bizarres
            return Response("OK", status=200, mimetype="text/plain")

        req, aes_key, iv, key_idx = decrypt_flow_payload_try_all_keys(body)

        action = req.get("action")
        version = req.get("version", "3.0")

        print(f"[FLOW] DECRYPTED action={action} using_key={key_idx} keys={list(req.keys())}", flush=True)

        # PING
        if action == "ping":
            resp_obj = {"version": version, "data": {"status": "active"}}
            encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
            return Response(encrypted, status=200, mimetype="text/plain")

        # DATA_EXCHANGE (final)
        # => on répond vite, et on laisse /webhook/whatsapp enregistrer avec le phone
        resp_obj = {"version": version, "data": {"ok": True}}
        encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
        return Response(encrypted, status=200, mimetype="text/plain")

    except Exception:
        app.logger.exception("[FLOW] Error")
        # même ici: 200 OK peut éviter l’erreur côté WhatsApp, mais gardons 400 pour debug.
        return Response("ERROR", status=400, mimetype="text/plain")

# Aliases pour Meta URL
@app.post("/api/survey/webhook")
@app.post("/webhook/flow")
def flow_alias():
    return flow_endpoint()

# =========================
# WhatsApp webhook (c’est LÀ que tu récupères phone + réponses)
# =========================
@app.get("/webhook/whatsapp")
def webhook_whatsapp_get():
    # Si tu fais la vérification Meta (hub.challenge), tu peux l’ajouter ici.
    return "OK", 200

@app.post("/webhook/whatsapp")
def webhook_whatsapp_post():
    try:
        body = request.get_json(force=True, silent=False) or {}
        ts = now_iso()

        msg = dig(body, "entry", 0, "changes", 0, "value", "messages", 0) or {}
        phone = str(msg.get("from", ""))

        it = msg.get("interactive") or {}
        if it.get("type") == "nfm_reply":
            nfm = it.get("nfm_reply") or {}
            resp_json_str = nfm.get("response_json", "{}")

            try:
                resp = json.loads(resp_json_str)
            except Exception:
                resp = {}

            q1 = resp.get("q1", "")
            q2 = resp.get("q2", "")
            q3 = resp.get("q3", "")
            campaign_id = resp.get("campaign_id", "")
            segment = resp.get("segment", "")

            # ✅ Ici tu as le phone + réponses
            append_row_to_sheet([
                ts, phone, "", campaign_id, segment, q1, q2, q3, json.dumps(body, ensure_ascii=False)
            ])
            return jsonify({"ok": True}), 200

        # Sinon: log brut
        append_row_to_sheet([ts, phone, "", "", "", "", "", "", json.dumps(body, ensure_ascii=False)])
        return jsonify({"ok": True}), 200

    except Exception:
        app.logger.exception("[WABA] Error")
        # On renvoie 200 pour éviter des retries Meta
        return jsonify({"ok": False}), 200

# =========================
# Optional classic webhook
# =========================
@app.get("/webhook")
def webhook_get():
    return "OK", 200

@app.post("/webhook")
def webhook_post():
    try:
        body = request.get_json(force=True, silent=False) or {}
        ts = now_iso()
        phone = str(dig(body, "from") or "")
        append_row_to_sheet([ts, phone, "", "", "", "", "", "", json.dumps(body, ensure_ascii=False)])
        return jsonify({"ok": True}), 200
    except Exception:
        app.logger.exception("[WEBHOOK] Error")
        return jsonify({"ok": False}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
