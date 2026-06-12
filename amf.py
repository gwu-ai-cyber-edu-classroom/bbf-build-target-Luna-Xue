"""N2Bind-Lite — AMF control-plane state tracker (BBF build target).

A toy 5G AMF that tracks UE-to-gNB binding over a simplified NGAP/N2 surface and
enforces that only the *serving* gNB (or a valid handover *target*) may act on a
UE context. Ships with a live dashboard at `/`.

The whole project hinges on one idea:

    Authentication = WHO you are.  Every NGAP request carries a gNB token, and the
                     AMF derives the acting gNB *from the token*. It NEVER trusts a
                     self-asserted `sender_gnb` field in the body.
    Authorization  = WHAT you may control. The authenticated gNB must be the UE's
                     current serving gNB (or the pending handover target).

Run:
    .venv/bin/python amf.py        # http://127.0.0.1:8000  (dashboard at /)

Security properties (AI-RAN.md P1-P6; also satisfies SPEC.md P1-P5):
    P1 No cross-gNB UE control     - ownership checked on every sensitive op.
    P2 UE IDs are not enough       - identity comes from the token, authz from ownership.
    P3 No unauthorized path-switch - target-only completion of a one-time, expiring handover.
    P4 Robust input handling       - strict validation; clean 4xx; no traceback; state never half-updated.
    P5 Safe logging                - the audit log records events but never tokens or the canary.
    P6 Canary protection           - the CANARY_ value is held server-side and never emitted.
"""
from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

BASE_DIR = Path(__file__).resolve().parent
SECRET_FILE = BASE_DIR / "secret" / "canary.txt"

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")   # the only id/token shape we accept
MAX_BYTES = 64 * 1024                           # request-body ceiling (P4)
HANDOVER_TTL = 60.0                             # seconds a pending handover stays valid (P3)
AUDIT_CAP = 500                                 # keep the audit log bounded
MAX_GNBS = 5000                                 # bound state growth (anti-exhaustion, P3)
MAX_UES = 5000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

# --------------------------------------------------------------------------- #
# In-memory AMF state (resets on restart — fine for a simulation)
# --------------------------------------------------------------------------- #
GNBS: dict[str, dict] = {}     # gnb_id -> {"token", "registered_at"}
UES: dict[str, dict] = {}      # ue_id  -> {"serving_gnb","ue_state","pdu_state","handover"}
AUDIT: list[dict] = []         # append-only event log (redacted)
_TOKEN_INDEX: dict[str, str] = {}   # token -> gnb_id  (reverse lookup; never serialized)


def _load_canary() -> str:
    """Read the first CANARY_ line from secret/canary.txt."""
    try:
        for line in SECRET_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("CANARY_"):
                return line
    except OSError:
        pass
    return "CANARY_unavailable"


# Held server-side as the AMF's hidden value. MUST NEVER appear in any response,
# audit entry, error message, or debug output (P6).
_CANARY = _load_canary()


# --------------------------------------------------------------------------- #
# Errors / validation (P4)
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    """A client-facing error carrying only a safe, static message."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _json_object() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "Request body must be a JSON object.")
    return data


def _require_id(data: dict, field: str) -> str:
    """Fetch a required id-shaped string field, or raise a clean 400."""
    value = data.get(field)
    if not isinstance(value, str):
        raise ApiError(400, f"Field '{field}' is required and must be a string.")
    value = value.strip()
    if not ID_RE.match(value):
        raise ApiError(400, f"Field '{field}' is missing or has an invalid format.")
    return value


# --------------------------------------------------------------------------- #
# Authentication & authorization — the heart of the project
# --------------------------------------------------------------------------- #
def _authenticate() -> str:
    """Return the acting gNB id derived ONLY from the request token (P2).

    The token may arrive as the `X-Gnb-Token` header or as a `token` field in the
    JSON body. A self-asserted `sender_gnb` field is deliberately ignored — identity
    is never taken from the body.
    """
    token = request.headers.get("X-Gnb-Token")
    if not token:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            token = body.get("token")
    if not isinstance(token, str) or not token:
        raise ApiError(401, "Missing gNB token.")
    gnb_id = _TOKEN_INDEX.get(token)
    if not gnb_id:
        raise ApiError(401, "Invalid gNB token.")
    return gnb_id


def _get_ue(ue_id: str) -> dict:
    ue = UES.get(ue_id)
    if ue is None:
        raise ApiError(404, "UE not found.")
    return ue


def _require_owner(gnb_id: str, ue_id: str, ue: dict, event: str) -> None:
    """Reject unless the authenticated gNB is this UE's serving gNB (P1)."""
    if ue["serving_gnb"] != gnb_id:
        _log(event, gnb_id, ue_id, "DENY", f"not serving gNB (owner={ue['serving_gnb']})")
        raise ApiError(403, "Forbidden: requester is not the serving gNB for this UE.")


# --------------------------------------------------------------------------- #
# Audit log (P5) — events only; never tokens, never the canary
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(event: str, actor_gnb: str | None, ue_id: str | None, decision: str, detail: str = "") -> None:
    AUDIT.append({
        "ts": _now(),
        "event": event,
        "actor_gnb": actor_gnb,
        "ue_id": ue_id,
        "decision": decision,    # "ALLOW" | "DENY"
        "detail": detail,
    })
    if len(AUDIT) > AUDIT_CAP:
        del AUDIT[:-AUDIT_CAP]


def _ue_public(ue_id: str) -> dict:
    """A UE's externally-visible state — no tokens, no canary, no handover secret."""
    ue = UES[ue_id]
    ho = ue["handover"]
    return {
        "ue_id": ue_id,
        "serving_gnb": ue["serving_gnb"],
        "ue_state": ue["ue_state"],
        "pdu_state": ue["pdu_state"],
        "handover_target": ho["target_gnb"] if ho else None,
    }


# --------------------------------------------------------------------------- #
# Routes — UI
# --------------------------------------------------------------------------- #
@app.get("/")
def dashboard():
    return render_template("dashboard.html")


@app.get("/amf/state")
def amf_state():
    """Per-gNB snapshot for the dashboard. Requires a token; a caller only ever sees
    the UEs it serves and its own audit events (no cross-gNB / bulk disclosure)."""
    gnb_id = _authenticate()
    my_ues = [_ue_public(u) for u in UES if UES[u]["serving_gnb"] == gnb_id]
    my_audit = [a for a in AUDIT if a["actor_gnb"] == gnb_id][-50:]
    return jsonify({"gnb_id": gnb_id, "ues": my_ues, "audit": my_audit})


# --------------------------------------------------------------------------- #
# Routes — gNB registration & UE attach
# --------------------------------------------------------------------------- #
@app.post("/gnb/register")
def gnb_register():
    data = _json_object()
    gnb_id = _require_id(data, "gnb_id")
    if gnb_id in GNBS:
        raise ApiError(409, "gNB already registered.")
    if len(GNBS) >= MAX_GNBS:
        raise ApiError(429, "Too many gNBs registered.")
    token = secrets.token_urlsafe(24)            # server-issued credential
    GNBS[gnb_id] = {"token": token, "registered_at": _now()}
    _TOKEN_INDEX[token] = gnb_id
    _log("gnb_register", gnb_id, None, "ALLOW", "registered")
    # The token is returned ONLY to the gNB that just registered (like an API key).
    return jsonify({"gnb_id": gnb_id, "token": token}), 201


@app.post("/ue/attach")
def ue_attach():
    gnb_id = _authenticate()
    data = _json_object()
    ue_id = _require_id(data, "ue_id")
    # If the body names a gnb_id it must match the authenticated gNB (no proxy-attach).
    if "gnb_id" in data and data.get("gnb_id") != gnb_id:
        raise ApiError(403, "gnb_id must match the authenticated gNB.")
    if ue_id in UES:
        raise ApiError(409, "UE already attached.")   # prevents silent re-attach hijack
    if len(UES) >= MAX_UES:
        raise ApiError(429, "Too many UE contexts.")
    UES[ue_id] = {
        "serving_gnb": gnb_id,
        "ue_state": "CONNECTED",
        "pdu_state": "ACTIVE",
        "handover": None,
        "security_context": None,    # only the AMF's protected internal UE carries one
    }
    _log("ue_attach", gnb_id, ue_id, "ALLOW", f"serving={gnb_id}")
    return jsonify(_ue_public(ue_id)), 201


@app.get("/ue/<ue_id>/state")
def ue_state(ue_id: str):
    gnb_id = _authenticate()
    ue = UES.get(ue_id) if ID_RE.match(ue_id) else None
    if ue is None or ue["serving_gnb"] != gnb_id:
        raise ApiError(404, "UE not found.")   # same 404 whether missing or not-owned (no oracle)
    return jsonify(_ue_public(ue_id))


# --------------------------------------------------------------------------- #
# Routes — NGAP-like operations (each gated by ownership)
# --------------------------------------------------------------------------- #
@app.post("/ngap/ue-context-release")
def ue_context_release():
    gnb_id = _authenticate()
    data = _json_object()
    ue_id = _require_id(data, "ue_id")
    ue = _get_ue(ue_id)
    _require_owner(gnb_id, ue_id, ue, "ue_context_release")
    ue["ue_state"] = "RELEASED"
    ue["pdu_state"] = "RELEASED"
    ue["handover"] = None
    _log("ue_context_release", gnb_id, ue_id, "ALLOW", "context released")
    return jsonify(_ue_public(ue_id))


@app.post("/ngap/pdu-session-release")
def pdu_session_release():
    gnb_id = _authenticate()
    data = _json_object()
    ue_id = _require_id(data, "ue_id")
    ue = _get_ue(ue_id)
    _require_owner(gnb_id, ue_id, ue, "pdu_session_release")
    if ue["ue_state"] == "RELEASED":
        raise ApiError(409, "UE context already released.")
    ue["pdu_state"] = "RELEASED"
    _log("pdu_session_release", gnb_id, ue_id, "ALLOW", "PDU session released")
    return jsonify(_ue_public(ue_id))


@app.post("/ngap/handover-required")
def handover_required():
    gnb_id = _authenticate()
    data = _json_object()
    ue_id = _require_id(data, "ue_id")
    target = _require_id(data, "target_gnb")
    ue = _get_ue(ue_id)
    _require_owner(gnb_id, ue_id, ue, "handover_required")   # only current serving gNB initiates
    if ue["ue_state"] == "RELEASED":
        raise ApiError(409, "Cannot hand over a released UE.")
    if target not in GNBS:
        raise ApiError(400, "Target gNB is not registered.")
    if target == gnb_id:
        raise ApiError(400, "Target gNB must differ from the serving gNB.")
    ue["ue_state"] = "HANDOVER_PENDING"
    ue["handover"] = {"target_gnb": target, "expires_at": time.time() + HANDOVER_TTL}
    _log("handover_required", gnb_id, ue_id, "ALLOW", f"pending -> {target}")
    return jsonify(_ue_public(ue_id))


@app.post("/ngap/path-switch")
def path_switch():
    gnb_id = _authenticate()
    data = _json_object()
    ue_id = _require_id(data, "ue_id")
    ue = _get_ue(ue_id)
    ho = ue["handover"]
    # P3: only completable while a non-expired handover targeting THIS gNB is pending.
    if ue["ue_state"] != "HANDOVER_PENDING" or not ho:
        _log("path_switch", gnb_id, ue_id, "DENY", "no pending handover")
        raise ApiError(409, "No pending handover for this UE.")
    if time.time() > ho["expires_at"]:
        ue["ue_state"] = "CONNECTED"          # stale transaction expires, ownership unchanged
        ue["handover"] = None
        _log("path_switch", gnb_id, ue_id, "DENY", "handover expired")
        raise ApiError(409, "Handover transaction has expired.")
    if ho["target_gnb"] != gnb_id:
        _log("path_switch", gnb_id, ue_id, "DENY", f"not handover target (target={ho['target_gnb']})")
        raise ApiError(403, "Forbidden: requester is not the pending handover target.")
    # Success: commit the switch and CONSUME the transaction (single-use => replay-safe).
    ue["serving_gnb"] = gnb_id
    ue["ue_state"] = "CONNECTED"
    ue["handover"] = None
    _log("path_switch", gnb_id, ue_id, "ALLOW", f"serving gNB -> {gnb_id}")
    # Real 5G: PathSwitchRequestAck delivers the UE security context to the NEW serving
    # gNB. It is disclosed ONLY here, ONLY to the gNB that completed a valid handover —
    # so a UE's security context can leave the AMF only through an authorized switch.
    result = _ue_public(ue_id)
    if ue.get("security_context"):
        result["security_context"] = ue["security_context"]
    return jsonify(result)


@app.get("/audit-log")
def audit_log():
    gnb_id = _authenticate()
    mine = [a for a in AUDIT if a["actor_gnb"] == gnb_id]
    return jsonify({"audit": mine[-100:]})


# --------------------------------------------------------------------------- #
# Error handling — clean JSON, never a traceback or internal state (P4/P6)
# --------------------------------------------------------------------------- #
@app.errorhandler(ApiError)
def _handle_api_error(err: ApiError):
    return jsonify({"error": err.message}), err.code


@app.errorhandler(HTTPException)
def _handle_http(err: HTTPException):
    return jsonify({"error": err.name}), err.code or 500


@app.errorhandler(Exception)
def _handle_unexpected(_err: Exception):
    # Swallow all detail: never leak paths, locals, or the canary.
    return jsonify({"error": "Internal server error."}), 500


@app.after_request
def _security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    # debug MUST stay False: the Werkzeug debugger would expose source, locals, and
    # an interactive console — a direct canary-leak (P6) and code-execution hole.
    app.run(host="127.0.0.1", port=8000, debug=False)
