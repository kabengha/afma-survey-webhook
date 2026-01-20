import os, json, logging
from flask import Flask, request, jsonify

app = Flask(__name__)

log = logging.getLogger("survey")
log.setLevel(logging.INFO)
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | SURVEY | %(levelname)s | %(message)s"))
    log.addHandler(h)

@app.get("/health")
def health():
    return "ok", 200

@app.post("/api/survey/webhook")
def survey_webhook():
    expected = os.getenv("SURVEY_WEBHOOK_SECRET", "")
    provided = request.headers.get("X-SURVEY-SECRET", "")
    if expected and provided != expected:
        log.warning("Unauthorized")
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    log.info("Payload: %s", json.dumps(payload, ensure_ascii=False)[:8000])

    return jsonify({"status": "ok"}), 200
