import threading
from flask import Flask, jsonify
from attack import run_attack

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    status = "attacking" if _attacking else "ready"
    return jsonify({"status": status, "scenario": "docker-socket-abuse"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=_run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "docker-socket-abuse"})


def _run_attack():
    global _attacking
    try:
        run_attack()
    finally:
        _attacking = False


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
