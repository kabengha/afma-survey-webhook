from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/survey/webhook", methods=["GET", "POST"])
def survey_webhook():
    if request.method == "GET":
        return jsonify({"status": "ok"}), 200

    # POST (tes messages / flow payload)
    data = request.get_json(silent=True) or {}
    return jsonify({"received": True}), 200
