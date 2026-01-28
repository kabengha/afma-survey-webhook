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



@app.get("/api/survey/webhook")
def flow_alias_get():
    return "OK", 200

# =========================
# Google Sheets
# =========================
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


def extract_phone_from_anywhere(obj: dict) -> str:
    candidates = [
        dig(obj, "from"),
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


# =========================
# Load multiple private keys
# =========================
def _load_one_key_from_pem(pem_str: str):
    passphrase = os.getenv("FLOW_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode("utf-8") if passphrase else None
    pem_bytes = pem_str.replace("\\n", "\n").encode("utf-8")
    return load_pem_private_key(pem_bytes, password=password)


def load_private_keys():
    keys = []

    # Prefer numbered keys
    for i in range(1, 6):
        pem = os.getenv(f"FLOW_PRIVATE_KEY_PEM_{i}")
        if pem:
            keys.append(_load_one_key_from_pem(pem))

    # Fallback single key
    pem_single = os.getenv("FLOW_PRIVATE_KEY_PEM")
    if pem_single:
        keys.append(_load_one_key_from_pem(pem_single))

    if not keys:
        raise RuntimeError("No private keys found. Set FLOW_PRIVATE_KEY_PEM or FLOW_PRIVATE_KEY_PEM_1")

    return keys


PRIVATE_KEYS = load_private_keys()
print(f"[BOOT] Loaded {len(PRIVATE_KEYS)} private key(s)", flush=True)


# =========================
# Meta Flows Crypto
# =========================
FLOW_REQUIRED_KEYS = {"encrypted_flow_data", "encrypted_aes_key", "initial_vector"}


def invert_iv(iv: bytes) -> bytes:
    return bytes((b ^ 0xFF) for b in iv)


def encrypt_flow_response(resp_obj: dict, aes_key: bytes, req_iv: bytes) -> str:
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
# Routes
# =========================
@app.get("/")
def root():
    return "OK", 200


@app.get("/health")
def health():
    return "OK", 200


@app.post("/flow")
def flow_endpoint():
    print("[FLOW] PATH=", request.path, flush=True)
    print("[FLOW] HIT", flush=True)
    print("[FLOW] UA=", request.headers.get("User-Agent", ""), flush=True)

    try:
        body = request.get_json(force=True, silent=False) or {}
        print("[FLOW] RAW keys=", list(body.keys()) if isinstance(body, dict) else str(type(body)), flush=True)

        ua = request.headers.get("User-Agent", "")
        app.logger.info(f"[FLOW] UA={ua}")
        app.logger.info(f"[FLOW] RAW keys={list(body.keys()) if isinstance(body, dict) else type(body)}")

        if not isinstance(body, dict) or not FLOW_REQUIRED_KEYS.issubset(set(body.keys())):
            app.logger.warning("[FLOW] Missing encrypted fields -> not a valid Meta Flows request")
            return Response("OK", status=200, mimetype="text/plain")


        req, aes_key, iv, key_idx = decrypt_flow_payload_try_all_keys(body)

        action = req.get("action")
        version = req.get("version", "3.0")
        print(f"[FLOW] DECRYPTED action={action} using_key={key_idx} data_keys={list((req.get('data') or {}).keys())}", flush=True)
        app.logger.info(f"[FLOW] DECRYPTED action={action} using_key={key_idx} keys={list(req.keys())}")

        # PING
        if action == "ping":
            resp_obj = {"version": version, "data": {"status": "active"}}
            encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
            return Response(encrypted, status=200, mimetype="text/plain")

        # SUBMIT / DATA EXCHANGE
        data = req.get("data") or {}
        flow_token = req.get("flow_token", "") or req.get("token", "")

        q1 = data.get("q1", "") or data.get("Q1", "") or ""
        q2 = data.get("q2", "") or data.get("Q2", "") or ""
        q3 = data.get("q3", "") or data.get("Q3", "") or ""

        campaign_id = data.get("campaign_id", "") or ""
        segment = data.get("segment", "") or ""

        phone = extract_phone_from_anywhere(req)

        ts = now_iso()
        raw_json = json.dumps(req, ensure_ascii=False)

        try:
            append_row_to_sheet([ts, phone, flow_token, campaign_id, segment, q1, q2, q3, raw_json])
        except Exception as e:
            print("[SHEETS] ERROR:", str(e), flush=True)
            # on continue quand même à répondre OK à Meta pour ne pas bloquer l'utilisateur


        resp_obj = {
            "version": version,
            "data": {
                "status": "success",
                "result": "ok"
            }
        }


        encrypted = encrypt_flow_response(resp_obj, aes_key, iv)
        return Response(encrypted, status=200, mimetype="text/plain")

    except Exception:
        app.logger.exception("[FLOW] Error")
        return Response("ERROR", status=400, mimetype="text/plain")


# Aliases for your Meta URL
@app.post("/api/survey/webhook")
@app.post("/webhook/flow")
def flow_alias():
    return flow_endpoint()

@app.post("/webhook/whatsapp")
def whatsapp_webhook_alias():
    return webhook()

@app.get("/webhook/whatsapp")
def whatsapp_webhook_alias_get():
    return "OK", 200



# Optional classic webhook
@app.post("/webhook")
def webhook():
    try:
        body = request.get_json(force=True, silent=False) or {}
        ts = now_iso()
        phone = extract_phone_from_anywhere(body)
        raw_json = json.dumps(body, ensure_ascii=False)
        append_row_to_sheet([ts, phone, "", "", "", "", "", "", raw_json])
        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("[WEBHOOK] Error")
        return jsonify({"ok": False, "error": str(e)}), 200


@app.get("/webhook")
def webhook_get():
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
