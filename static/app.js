"use strict";

// gNB tokens are kept in this page's memory only (never persisted, never shown
// to other gNBs). Each registered gNB acts with its own token.
const TOKENS = {};
const $ = (id) => document.getElementById(id);

const OP_PATHS = {
  "ue-context-release": "/ngap/ue-context-release",
  "pdu-session-release": "/ngap/pdu-session-release",
  "handover-required": "/ngap/handover-required",
  "path-switch": "/ngap/path-switch",
};

// --------------------------------------------------------------------------- //
// API helper + console logging
// --------------------------------------------------------------------------- //
async function api(method, path, { body = null, gnb = null } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (gnb && TOKENS[gnb]) headers["X-Gnb-Token"] = TOKENS[gnb];
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  let status = 0, json = {};
  try {
    const res = await fetch(path, opts);
    status = res.status;
    json = await res.json().catch(() => ({}));
  } catch (e) {
    json = { error: String(e) };
  }
  logConsole(method, path, gnb, body, status, json);
  return { status, json };
}

function logConsole(method, path, gnb, body, status, json) {
  const entry = document.createElement("div");
  entry.className = "log-entry";

  const req = document.createElement("div");
  req.className = "log-req";
  const m = document.createElement("span");
  m.className = "log-method";
  m.textContent = method + " " + path;
  req.appendChild(m);
  if (gnb) {
    const t = document.createElement("span");
    t.className = "log-token";
    t.textContent = "   X-Gnb-Token: " + gnb;
    req.appendChild(t);
  }
  entry.appendChild(req);

  if (body) {
    const b = document.createElement("pre");
    b.className = "log-body";
    b.textContent = JSON.stringify(body);
    entry.appendChild(b);
  }

  const resp = document.createElement("pre");
  const cls = status >= 200 && status < 300 ? "ok" : status >= 400 && status < 500 ? "warn" : "err";
  resp.className = "log-resp " + cls;
  resp.textContent = "← " + status + "  " + JSON.stringify(json);
  entry.appendChild(resp);

  const c = $("console");
  c.insertBefore(entry, c.firstChild);
}

// --------------------------------------------------------------------------- //
// gNB selectors / chips
// --------------------------------------------------------------------------- //
function refreshGnbUI() {
  const ids = Object.keys(TOKENS);
  for (const selId of ["attachGnb", "opGnb", "opTarget"]) {
    const sel = $(selId);
    const prev = sel.value;
    sel.textContent = "";
    for (const id of ids) {
      const o = document.createElement("option");
      o.value = id;
      o.textContent = id;
      sel.appendChild(o);
    }
    if (ids.includes(prev)) sel.value = prev;
  }
  const list = $("gnbList");
  list.textContent = "";
  if (!ids.length) {
    const e = document.createElement("span");
    e.className = "muted";
    e.textContent = "No gNBs registered yet.";
    list.appendChild(e);
    return;
  }
  for (const id of ids) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = id;
    const k = document.createElement("span");
    k.className = "chip-key";
    k.textContent = "🔑";
    chip.appendChild(k);
    list.appendChild(chip);
  }
}

// --------------------------------------------------------------------------- //
// Actions
// --------------------------------------------------------------------------- //
async function registerGnb() {
  const id = $("gnbId").value.trim();
  if (!id) return;
  const { status, json } = await api("POST", "/gnb/register", { body: { gnb_id: id } });
  if (status === 201 && json.token) {
    TOKENS[json.gnb_id] = json.token;
    $("gnbId").value = "";
    refreshGnbUI();
    renderState();
  }
}

async function attachUe() {
  const ue = $("attachUe").value.trim();
  const gnb = $("attachGnb").value;
  if (!ue || !gnb) return;
  await api("POST", "/ue/attach", { body: { ue_id: ue }, gnb });
  $("attachUe").value = "";
  renderState();
}

async function sendOp() {
  const op = $("opType").value;
  const gnb = $("opGnb").value;
  const ue = $("opUe").value.trim();
  if (!gnb || !ue) return;
  const body = { ue_id: ue };
  if (op === "handover-required") body.target_gnb = $("opTarget").value;
  const spoof = $("opSpoof").value.trim();
  if (spoof) body.sender_gnb = spoof; // server should IGNORE this (identity comes from token)
  await api("POST", OP_PATHS[op], { body, gnb });
  renderState();
}

// --------------------------------------------------------------------------- //
// Demo + attack presets
// --------------------------------------------------------------------------- //
async function loadDemo() {
  for (const g of ["gNB-A", "gNB-B", "gNB-C"]) {
    if (TOKENS[g]) continue;
    const { status, json } = await api("POST", "/gnb/register", { body: { gnb_id: g } });
    if (status === 201) TOKENS[g] = json.token;
  }
  refreshGnbUI();
  await api("POST", "/ue/attach", { body: { ue_id: "UE-001" }, gnb: "gNB-A" });
  await api("POST", "/ue/attach", { body: { ue_id: "UE-002" }, gnb: "gNB-B" });
  await api("POST", "/ue/attach", { body: { ue_id: "UE-003" }, gnb: "gNB-A" });
  renderState();
}

function preset(op, gnb, ue, target, spoof) {
  $("opType").value = op;
  toggleTargetRow();
  $("opGnb").value = gnb;
  $("opUe").value = ue;
  if (target) $("opTarget").value = target;
  $("opSpoof").value = spoof || "";
}

function toggleTargetRow() {
  const show = $("opType").value === "handover-required";
  $("targetRow").classList.toggle("hidden", !show);
}

// --------------------------------------------------------------------------- //
// Render state
// --------------------------------------------------------------------------- //
async function renderState() {
  // /amf/state is token-scoped and per-gNB: each call returns only the calling
  // gNB's UEs + audit events. Fetch once per registered gNB and merge for the view.
  const gnbs = Object.keys(TOKENS);
  $("gnbCount").textContent = gnbs.length;

  const ues = [];
  let audit = [];
  for (const g of gnbs) {
    let s;
    try {
      const res = await fetch("/amf/state", { headers: { "X-Gnb-Token": TOKENS[g] } });
      if (!res.ok) continue;
      s = await res.json();
    } catch (e) {
      continue;
    }
    if (Array.isArray(s.ues)) ues.push(...s.ues);
    if (Array.isArray(s.audit)) audit = audit.concat(s.audit);
  }
  // Newest audit events first, regardless of which gNB they came from.
  audit.sort((a, b) => String(a.ts).localeCompare(String(b.ts)));

  const ueBody = $("ueRows");
  ueBody.textContent = "";
  if (!ues.length) {
    ueBody.appendChild(emptyRow(5, "No UE contexts yet."));
  } else {
    for (const u of ues) {
      const tr = document.createElement("tr");
      tr.appendChild(td(u.ue_id, "mono"));
      tr.appendChild(td(u.serving_gnb, "mono"));
      tr.appendChild(badgeCell(u.ue_state, stateClass(u.ue_state)));
      tr.appendChild(badgeCell(u.pdu_state, u.pdu_state === "ACTIVE" ? "b-ok" : "b-off"));
      tr.appendChild(td(u.handover_target || "—", "mono"));
      ueBody.appendChild(tr);
    }
  }

  const aBody = $("auditRows");
  aBody.textContent = "";
  const items = audit.slice().reverse();
  if (!items.length) {
    aBody.appendChild(emptyRow(5, "No events yet."));
  } else {
    for (const a of items) {
      const tr = document.createElement("tr");
      tr.appendChild(td((a.ts || "").replace("T", " ").replace("Z", ""), "mono dim"));
      tr.appendChild(td(a.event, "mono"));
      tr.appendChild(td(a.actor_gnb || "—", "mono"));
      tr.appendChild(td(a.ue_id || "—", "mono"));
      tr.appendChild(badgeCell(a.decision, a.decision === "ALLOW" ? "b-ok" : "b-deny"));
      aBody.appendChild(tr);
    }
  }
}

function stateClass(s) {
  if (s === "CONNECTED") return "b-ok";
  if (s === "HANDOVER_PENDING") return "b-warn";
  return "b-off";
}
function td(text, cls) {
  const d = document.createElement("td");
  if (cls) d.className = cls;
  d.textContent = text;
  return d;
}
function badgeCell(text, cls) {
  const d = document.createElement("td");
  const b = document.createElement("span");
  b.className = "badge " + cls;
  b.textContent = text;
  d.appendChild(b);
  return d;
}
function emptyRow(span, text) {
  const tr = document.createElement("tr");
  const d = document.createElement("td");
  d.colSpan = span;
  d.className = "muted center";
  d.textContent = text;
  tr.appendChild(d);
  return tr;
}

// --------------------------------------------------------------------------- //
// Wire up
// --------------------------------------------------------------------------- //
function init() {
  $("btnRegister").addEventListener("click", registerGnb);
  $("gnbId").addEventListener("keydown", (e) => { if (e.key === "Enter") registerGnb(); });
  $("btnAttach").addEventListener("click", attachUe);
  $("btnSend").addEventListener("click", sendOp);
  $("opType").addEventListener("change", toggleTargetRow);
  $("btnDemo").addEventListener("click", loadDemo);
  $("btnClearConsole").addEventListener("click", () => { $("console").textContent = ""; });
  $("presetCross").addEventListener("click", () => preset("ue-context-release", "gNB-B", "UE-001", null, null));
  $("presetSpoof").addEventListener("click", () => preset("ue-context-release", "gNB-B", "UE-001", null, "gNB-A"));
  $("presetFakeSwitch").addEventListener("click", () => preset("path-switch", "gNB-B", "UE-003", null, null));
  $("presetHandover").addEventListener("click", () => preset("handover-required", "gNB-A", "UE-001", "gNB-B", null));
  toggleTargetRow();
  refreshGnbUI();
  renderState();
  setInterval(renderState, 4000);
}
document.addEventListener("DOMContentLoaded", init);
