import os
import json
from datetime import datetime, timezone

from flask import Flask, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__)

# ----------------------------
# Google Sheets client
# ----------------------------
def get_gspread_client():
    """
    Uses a service account.
    Preferred: put the whole JSON in env var GOOGLE_SERVICE_ACCOUNT_JSON
    Alternative: use a file path via GOOGLE_SERVICE_ACCOUNT_FILE
    """
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
        raise RuntimeError("Missing GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_FILE")

    return gspread.authorize(creds)

def append_row_to_sheet(row):
    sheet_id = os.getenv("GSHEET_ID")
    tab_name = os.getenv("GSHEET_TAB", "Sheet1")

    if not sheet_id:
        raise RuntimeError("Missing SHEET_ID env var")

    gc = get_gspread_client()
    sh = gc.open_by_key(sheet_id)
    ws = sh.worksheet(tab_name)
    ws.append_row(row, value_input_option="RAW")

# ----------------------------
# Helpers: extract useful fields
# ----------------------------
def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def dig(d, *keys):
    """Safely get nested dict keys in order."""
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur

def extract_payload(body: dict) -> dict:
    """
    Try to find where the flow answers live.
    We'll look in common places:
    - body itself
    - body["payload"]
    - body["flow"]
    - body["data"]
    - body["content"]["data"]
    """
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
        if isinstance(c, dict) and any(k in c for k in ["q1", "q2", "q3", "campaign_id", "segment"]):
            return c
    # fallback: return empty dict
    return {}

def extract_from(body: dict) -> str:
    return (
        str(dig(body, "from"))
        or str(dig(body, "sender"))
        or str(dig(body, "contact", "phone"))
        or str(dig(body, "message", "from"))
        or ""
    )

@app.post("/webhook")
def webhook():
    try:
        body = request.get_json(force=True, silent=False) or {}
        payload = extract_payload(body)

        # Extract fields
        phone = extract_from(body)
        ts = now_iso()

        campaign_id = payload.get("campaign_id") or dig(body, "campaign_id") or ""
        segment = payload.get("segment") or dig(body, "segment") or ""

        q1 = payload.get("q1", "")
        q2 = payload.get("q2", "")
        q3 = payload.get("q3", "")

        raw_json = json.dumps(payload if payload else body, ensure_ascii=False)

        row = [ts, phone, campaign_id, segment, q1, q2, q3, raw_json]
        append_row_to_sheet(row)

        return jsonify({"ok": True, "appended": row}), 200

    except Exception as e:
        # Log server side
        app.logger.exception("Webhook error")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/health")
def health():
    return "OK", 200
