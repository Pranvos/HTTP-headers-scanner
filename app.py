from flask import Flask, jsonify, render_template, request

from scanner import scan_url

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
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
