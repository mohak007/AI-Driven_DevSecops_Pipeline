"""
AI-Based Security Monitoring System — Phase 1
Flask login app with structured JSON logging.

Every login attempt (success or failure) is logged as a JSON object
so the ELK stack (Phase 2) and ML engine (Phase 3) can consume it directly.
"""

import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Structured JSON logger
# ---------------------------------------------------------------------------
# We replace Flask's default handler with one that emits pure JSON lines.
# One JSON object per line = easy to parse by Logstash / any log aggregator.

class JSONFormatter(logging.Formatter):
    """Format every log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra fields passed as keyword arguments to the logger
        if hasattr(record, "extra"):
            base.update(record.extra)
        return json.dumps(base)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()          # stdout → Docker captures this
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    return logger


security_logger = get_logger("security")
app_logger      = get_logger("app")

# ---------------------------------------------------------------------------
# In-memory state (replace with Redis in production)
# ---------------------------------------------------------------------------
# Structure: { ip: { "count": int, "first_seen": float, "last_seen": float } }
failed_attempts: dict = defaultdict(lambda: {"count": 0, "first_seen": 0.0, "last_seen": 0.0})

# Brute-force threshold: 5 failures within a 60-second window
MAX_FAILURES  = 5
WINDOW_SECS   = 60
LOCKOUT_SECS  = 300   # 5-minute lockout after threshold

# Fake user store (replace with DB in production)
USERS = {
    "admin": "secret123",
    "alice": "alicepass",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_event(event_type: str, extra: dict) -> None:
    """Emit a structured security event. Always includes a trace_id."""
    extra.update({
        "event_type": event_type,
        "trace_id": str(uuid.uuid4()),
    })
    security_logger.info(event_type, extra={"extra": extra})


def is_locked_out(ip: str) -> bool:
    state = failed_attempts[ip]
    if state["count"] >= MAX_FAILURES:
        elapsed = time.time() - state["last_seen"]
        if elapsed < LOCKOUT_SECS:
            return True
        # Lockout expired — reset
        failed_attempts[ip] = {"count": 0, "first_seen": 0.0, "last_seen": 0.0}
    return False


def record_failure(ip: str, username: str) -> None:
    state = failed_attempts[ip]
    now   = time.time()
    if state["count"] == 0:
        state["first_seen"] = now
    # Reset window if first failure was outside the window
    if now - state["first_seen"] > WINDOW_SECS:
        state.update({"count": 1, "first_seen": now, "last_seen": now})
    else:
        state["count"] += 1
        state["last_seen"] = now

    log_event("LOGIN_FAILURE", {
        "ip":            ip,
        "username":      username,
        "failure_count": state["count"],
        "window_secs":   WINDOW_SECS,
        "threshold":     MAX_FAILURES,
    })

    if state["count"] >= MAX_FAILURES:
        log_event("BRUTE_FORCE_DETECTED", {
            "ip":              ip,
            "username":        username,
            "failure_count":   state["count"],
            "lockout_seconds": LOCKOUT_SECS,
            "severity":        "HIGH",
        })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Liveness probe — used by Docker and load balancers."""
    return jsonify({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/login", methods=["POST"])
def login():
    """
    POST /login
    Body: { "username": "...", "password": "..." }
    Returns: 200 on success, 401 on bad creds, 423 if locked out.
    """
    ip       = request.headers.get("X-Forwarded-For", request.remote_addr)
    body     = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")
    ua       = request.headers.get("User-Agent", "unknown")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # --- Lockout check ---
    if is_locked_out(ip):
        log_event("LOGIN_BLOCKED", {
            "ip":       ip,
            "username": username,
            "reason":   "too_many_failures",
            "severity": "HIGH",
        })
        return jsonify({"error": "Too many failed attempts. Try again later."}), 423

    # --- Credential check ---
    stored = USERS.get(username)
    if stored and stored == password:
        # Reset failure counter on success
        failed_attempts[ip] = {"count": 0, "first_seen": 0.0, "last_seen": 0.0}
        log_event("LOGIN_SUCCESS", {
            "ip":       ip,
            "username": username,
            "ua":       ua,
        })
        return jsonify({"message": "Login successful", "user": username}), 200

    # --- Failed attempt ---
    record_failure(ip, username)
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/status", methods=["GET"])
def status():
    """Return current IP block list — useful for monitoring dashboards."""
    locked = {
        ip: state for ip, state in failed_attempts.items()
        if state["count"] >= MAX_FAILURES
    }
    return jsonify({
        "total_tracked_ips": len(failed_attempts),
        "currently_locked":  len(locked),
        "locked_ips":        list(locked.keys()),
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app_logger.info("Starting AI-DevSecOps Flask app", extra={
        "extra": {"port": 5000, "env": "development"}
    })
    # Debug=False in production; use gunicorn (see Dockerfile)
    app.run(host="0.0.0.0", port=5000, debug=False)
