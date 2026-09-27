from collections import defaultdict, deque
from time import time

from flask import Flask, jsonify, render_template, request

from scanner import scan_url

app = Flask(__name__)

MAX_SCANS_PER_HOUR = 20
WINDOW_SECONDS = 3600
request_times = defaultdict(deque)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
    client_ip = request.remote_addr or "unknown"
    now = time()
    times = request_times[client_ip]

    while times and now - times[0] > WINDOW_SECONDS:
        times.popleft()

    if len(times) >= MAX_SCANS_PER_HOUR:
        return jsonify({
            "error": "Rate limit exceeded. You can perform up to 20 scans per hour. Please try again later."
        }), 429

    times.append(now)

    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or request.form.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    try:
        report = scan_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Unable to scan that URL. Please verify it is reachable and try again."}), 400

    return jsonify(report)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
