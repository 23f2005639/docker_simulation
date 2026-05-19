import subprocess
import threading
from flask import Flask, jsonify

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    status = "attacking" if _attacking else "ready"
    return jsonify({"status": status, "scenario": "lateral-movement"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=_run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "lateral-movement"})


def _run_attack():
    global _attacking
    try:
        subprocess.run(["/bin/bash", "/attack.sh"], check=False)
    finally:
        _attacking = False


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
