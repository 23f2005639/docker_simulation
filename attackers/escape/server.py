import subprocess
import threading
from flask import Flask, jsonify

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "container-escape-CVE-2024-21626"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=_run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "container-escape-CVE-2024-21626"})


def _run_attack():
    global _attacking
    try:
        subprocess.run(["/bin/bash", "/attack.sh"], check=False)
    finally:
        _attacking = False


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
