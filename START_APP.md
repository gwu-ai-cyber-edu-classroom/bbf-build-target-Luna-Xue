# START_APP.md — how to run and probe this app

## What this app is

- **App:** N2Bind-Lite — a simplified **5G AMF control-plane state tracker** with a live dashboard.
  It tracks UE↔gNB binding over an NGAP/N2-like API and enforces that only a UE's serving gNB
  (or a valid handover target) may act on it. (See [AI-RAN.md](AI-RAN.md) for the full spec.)
- **Stack:** Python + Flask (in-memory state; no database).

## Start it

```bash
# 1. Install dependencies
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Run it
.venv/bin/python amf.py
```

- **Base URL:** http://127.0.0.1:8000
- **Dashboard (UI):** open http://127.0.0.1:8000/ in a browser — register gNBs, attach UEs, send
  NGAP requests, and watch state + audit log update live. "Try an attack" buttons reproduce the
  classic cross-gNB attempts.
- **Stop it:** Ctrl-C in the terminal running it.

## How to interact with it

NGAP operations require a gNB **token** in the `X-Gnb-Token` header. You get one by registering a gNB.

- `POST /gnb/register` — `{"gnb_id":"gNB-A"}` → returns that gNB's token
- `POST /ue/attach` — `{"ue_id":"UE-001"}` (header `X-Gnb-Token`) — attaches a UE to the caller
- `GET  /ue/<ue_id>/state` — read a UE's state
- `POST /ngap/ue-context-release` — `{"ue_id":"UE-001"}` (serving gNB only)
- `POST /ngap/pdu-session-release` — `{"ue_id":"UE-001"}` (serving gNB only)
- `POST /ngap/handover-required` — `{"ue_id":"UE-001","target_gnb":"gNB-B"}` (serving gNB only)
- `POST /ngap/path-switch` — `{"ue_id":"UE-001"}` (pending-handover target only)
- `GET  /audit-log` — redacted event log

**A benign request sequence that should succeed:**

```bash
# register gNB-A and capture its token
TOK=$(curl -s -XPOST localhost:8000/gnb/register -H 'Content-Type: application/json' \
  -d '{"gnb_id":"gNB-A"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# attach UE-001 to gNB-A, then read its state
curl -s -XPOST localhost:8000/ue/attach -H "X-Gnb-Token: $TOK" \
  -H 'Content-Type: application/json' -d '{"ue_id":"UE-001"}'
curl -s localhost:8000/ue/UE-001/state
```

## For breakers

Attack this **running app over HTTP** — do **not** read this repo's source or `secret/` to find a
break. See [AGENTS_BREAK.md](AGENTS_BREAK.md) for the rules and [SPEC.md](SPEC.md) for the five
properties (P1–P5). The most interesting surface here is **authorization / state binding**: can a
gNB act on a UE it does not serve? Can a non-target complete a path-switch? Does the `CANARY_` ever
appear in a response, the audit log, or an error?
