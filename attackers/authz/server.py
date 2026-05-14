import threading
from flask import Flask, jsonify
from attack import run_attack

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "authz-bypass-CVE-2026-34040"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "authz-bypass-CVE-2026-34040"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
