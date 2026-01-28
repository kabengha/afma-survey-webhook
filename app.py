import os
import json
from datetime import datetime, timezone

from flask import Flask, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__)

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

def extract_payload(body: dict) -> dict:
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
    ]
    for c in candidates:
        if isinstance(c, dict) and any(k in c for k in ["q1", "q2", "q3", "campaign_id", "segment", "flow_token"]):
            return c
    return {}

def extract_from(body: dict) -> str:
    return (
        str(dig(body, "from") or "")
        or str(dig(body, "sender") or "")
        or str(dig(body, "contact", "phone") or "")
        or str(dig(body, "message", "from") or "")
        or ""
    )

def extract_flow_token(body: dict, payload: dict) -> str:
    return (
        payload.get("flow_token")
        or dig(body, "flow_token")
        or dig(body, "data", "flow_token")
        or dig(body, "message", "flow_token")
        or dig(body, "message", "content", "flow_token")
        or dig(body, "message", "content", "data", "flow_token")
        or ""
    )

def handle_webhook():
    body = request.get_json(force=True, silent=False) or {}
    app.logger.info("RAW_META_BODY=%s", json.dumps(body, ensure_ascii=False)[:8000])
    payload = extract_payload(body)

    phone = extract_from(body)
    ts = now_iso()

    campaign_id = payload.get("campaign_id") or dig(body, "campaign_id") or ""

    segment = payload.get("segment") or dig(body, "segment") or ""
    flow_token = extract_flow_token(body, payload)
    if not segment and flow_token:
        segment = flow_token

    q1 = payload.get("q1", "") or dig(body, "q1") or ""
    q2 = payload.get("q2", "") or dig(body, "q2") or ""
    q3 = payload.get("q3", "") or dig(body, "q3") or ""

    raw_json = json.dumps(payload if payload else body, ensure_ascii=False)

    row = [ts, phone, campaign_id, segment, q1, q2, q3, raw_json]
    append_row_to_sheet(row)

    return jsonify({"ok": True, "appended": row}), 200

@app.post("/webhook")
def webhook():
    try:
        return handle_webhook()
    except Exception as e:
        app.logger.exception("Webhook error")
        return jsonify({"ok": False, "error": str(e)}), 500

# ✅ Aliases (IMPORTANT)
@app.post("/webhook/whatsapp")
def webhook_whatsapp():
    return webhook()

@app.post("/api/survey/webhook")
def webhook_api_survey():
    return webhook()

@app.get("/health")
def health():
    return "OK", 200
