# N2Bind-Lite: Build/Break/Fix Lab for 5G Control-Plane State Binding

## 1. Project Overview

**N2Bind-Lite** is a course project designed to help students understand security issues in the 5G control plane, especially around the N2 interface between the gNB and the AMF. The project asks students to build a simplified AMF state-tracking application, attack peer implementations, and then fix their own design based on discovered vulnerabilities.

The central idea is simple:

> A UE context should not be controlled only by valid UE identifiers. It should also be bound to the correct serving gNB or NG association.

In a real 5G system, the AMF maintains UE-related state and processes NGAP messages from gNBs. If the AMF accepts a control-plane request only because the UE ID is valid, without verifying whether the sender is authorized to act on that UE, a malicious or misconfigured gNB may be able to disrupt another gNB’s UE sessions.

This project creates a toy but meaningful version of this problem.

Students will build a small web/API application that simulates:

* gNB registration;
* UE attachment to a serving gNB;
* UE context release;
* PDU session release;
* handover or path switch events;
* AMF-side ownership checks;
* audit logging and error handling.

The project follows a **Build / Break / Fix** structure:

1. **Build:** implement a working AMF state tracker.
2. **Break:** test other teams’ implementations for logic flaws and security bugs.
3. **Fix:** patch vulnerabilities and explain the defense design.

The project is not intended to interact with a real 5G network. It is a sandboxed educational simulation for understanding control-plane state integrity.

---

## 2. Motivation

Modern 5G and O-RAN systems rely on complex control-plane interactions among gNBs, AMFs, RIC components, xApps, and cloud-native infrastructure. Many security discussions focus on cryptography, authentication, or network isolation. However, even when a sender is technically accepted by the system, the receiver still needs to verify whether the sender is authorized to act on a specific piece of state.

This project focuses on a subtle but important security principle:

> Authentication proves who the sender is.
> State binding verifies what the sender is allowed to control.

For example, suppose the AMF stores the following state:

```text
UE-1 is served by gNB-A.
UE-2 is served by gNB-B.
```

A secure AMF should accept a `UEContextReleaseRequest` for `UE-1` only from `gNB-A`, or from a properly authorized handover/mobility procedure. If `gNB-B` sends a release request for `UE-1`, the AMF should reject it, even if the UE ID itself is valid.

This lab allows students to explore this idea through a hands-on application.

---

## 3. Learning Objectives

After completing this project, students should be able to:

1. Explain the role of the N2 interface and NGAP-like control messages in a simplified 5G core.
2. Describe why UE context ownership must be bound to the serving gNB or NG association.
3. Identify state-confusion vulnerabilities in control-plane applications.
4. Design authorization checks beyond basic ID validation.
5. Use AI-assisted development and testing responsibly in a cybersecurity workflow.
6. Write a structured security report describing attacks, impact, and fixes.
7. Reflect on how similar state-binding issues may appear in O-RAN, private 5G, and cloud-native network systems.

---

## 4. System Model

The project simulates a small 5G control-plane environment with three main entities:

### 4.1 AMF Simulator

The AMF simulator maintains the global control-plane state.

It should store:

```text
gNB identity
UE identity
UE serving gNB
UE state
PDU session state
timestamp of recent events
audit logs
```

Example state:

```json
{
  "ue_id": "UE-001",
  "serving_gnb": "gNB-A",
  "ue_state": "CONNECTED",
  "pdu_session": "ACTIVE"
}
```

### 4.2 gNB Clients

Each gNB is represented as a logical client. A gNB can send simplified NGAP-like requests to the AMF simulator.

Example gNBs:

```text
gNB-A
gNB-B
gNB-C
```

Each gNB may have its own token, API key, or session identity.

### 4.3 UE Contexts

Each UE is attached to one serving gNB at a time.

Example:

```text
UE-001 -> gNB-A
UE-002 -> gNB-B
UE-003 -> gNB-A
```

The AMF should enforce that only the correct serving gNB can perform sensitive operations on the UE context, unless a valid mobility procedure is in progress.

---

## 5. Required Application Functions

Each team should build a small API-based application. A simple web dashboard is optional but encouraged.

Minimum required endpoints:

```http
POST /gnb/register
POST /ue/attach
GET  /ue/{ue_id}/state
POST /ngap/ue-context-release
POST /ngap/pdu-session-release
POST /ngap/handover-required
POST /ngap/path-switch
GET  /audit-log
```

The exact API format can be adjusted by each team, but the application must support the following operations.

---

## 6. Core Features

### 6.1 gNB Registration

The application should allow a gNB to register with the AMF simulator.

Example request:

```json
{
  "gnb_id": "gNB-A",
  "token": "team-defined-token"
}
```

Expected behavior:

* accept valid gNB registration;
* reject duplicate or malformed registration;
* maintain a mapping between gNB identity and authentication token/session.

---

### 6.2 UE Attachment

The application should allow a UE to attach to a serving gNB.

Example request:

```json
{
  "ue_id": "UE-001",
  "gnb_id": "gNB-A"
}
```

Expected behavior:

* create a UE context;
* bind the UE to the serving gNB;
* initialize the UE state as `CONNECTED`;
* initialize the PDU session state as `ACTIVE`.

---

### 6.3 UE Context Release

The application should support a simplified UE context release request.

Example request:

```json
{
  "sender_gnb": "gNB-A",
  "ue_id": "UE-001",
  "reason": "radio-connection-lost"
}
```

Secure expected behavior:

* verify that the sender gNB is registered;
* verify that the UE exists;
* verify that the sender gNB is the serving gNB for this UE;
* reject the request if another gNB tries to release the UE;
* update UE state only after successful verification;
* record the event in the audit log.

---

### 6.4 PDU Session Release

The application should support a simplified PDU session release request.

Example request:

```json
{
  "sender_gnb": "gNB-A",
  "ue_id": "UE-001",
  "pdu_session_id": "PDU-1"
}
```

Secure expected behavior:

* verify gNB ownership of the UE context;
* reject cross-gNB release attempts;
* update the PDU session state only after authorization;
* record success and failure events.

---

### 6.5 Handover and Path Switch

The application should support a simplified handover process.

Example sequence:

```text
1. UE-001 is served by gNB-A.
2. gNB-A sends HandoverRequired to move UE-001 to gNB-B.
3. AMF marks UE-001 as HANDOVER_PENDING.
4. gNB-B sends PathSwitchRequest.
5. AMF updates UE-001 serving gNB from gNB-A to gNB-B.
```

Secure expected behavior:

* only the current serving gNB can initiate handover;
* only the target gNB in the pending handover state can complete path switch;
* unrelated gNBs cannot hijack the UE context;
* stale handover states should expire or be rejected.

---

## 7. Security Properties

The implementation should satisfy the following security properties.

### P1. No Cross-gNB UE Control

A gNB must not be able to release, modify, or hijack a UE context owned by another gNB.

### P2. UE IDs Alone Are Not Enough

A request should not be accepted only because the UE ID is valid. The application must verify the sender’s authority over that UE.

### P3. No Unauthorized Handover Completion

A gNB should not be able to complete a path switch unless it is the intended target of a valid pending handover.

### P4. Robust Input Handling

Malformed, missing, oversized, or unexpected input should not crash the application or corrupt the AMF state.

### P5. Safe Logging

The audit log should record important security events, but it should not leak sensitive tokens, hidden secrets, or internal-only values.

### P6. Canary Protection

Each team should include a hidden value beginning with:

```text
CANARY_
```

The application must not expose this value through API responses, logs, error messages, debug pages, or AI-generated explanations.

---

## 8. Example Attack Scenarios

During the Break phase, students will test other teams’ applications. The goal is to find real vulnerabilities and report them clearly.

### Attack 1: Cross-gNB UE Context Release

Initial state:

```text
UE-001 is served by gNB-A.
gNB-B is registered but does not own UE-001.
```

Attack attempt:

```json
{
  "sender_gnb": "gNB-B",
  "ue_id": "UE-001",
  "reason": "normal-release"
}
```

Vulnerability condition:

```text
The AMF accepts the request and releases UE-001.
```

Expected secure behavior:

```text
The AMF rejects the request because gNB-B does not own UE-001.
```

---

### Attack 2: Cross-gNB PDU Session Release

Initial state:

```text
UE-002 is served by gNB-A.
PDU session is ACTIVE.
```

Attack attempt:

```json
{
  "sender_gnb": "gNB-B",
  "ue_id": "UE-002",
  "pdu_session_id": "PDU-1"
}
```

Vulnerability condition:

```text
The PDU session is released even though the sender is not the serving gNB.
```

---

### Attack 3: Fake Path Switch

Initial state:

```text
UE-003 is served by gNB-A.
No handover is pending.
```

Attack attempt:

```json
{
  "sender_gnb": "gNB-B",
  "ue_id": "UE-003"
}
```

Vulnerability condition:

```text
The AMF updates UE-003's serving gNB to gNB-B without a valid handover procedure.
```

---

### Attack 4: Stale Handover Replay

Initial state:

```text
UE-004 was previously handed over from gNB-A to gNB-B.
The old handover transaction should no longer be valid.
```

Attack attempt:

```text
Replay an old path-switch or handover-complete request.
```

Vulnerability condition:

```text
The AMF accepts the stale request and corrupts UE ownership state.
```

---

### Attack 5: Canary Leakage

Attack attempt:

```text
Trigger debug output, error messages, logs, AI explanations, or admin pages to reveal a hidden CANARY_ value.
```

Vulnerability condition:

```text
The response contains the CANARY_ value.
```

---

## 9. Suggested Technology Stack

Students may choose any simple implementation stack.

Recommended options:

### Option A: Python

```text
FastAPI or Flask
SQLite or in-memory dictionary
pytest for testing
curl/Postman for API testing
```

### Option B: JavaScript

```text
Node.js
Express
JSON file or in-memory object
Jest for testing
```

### Option C: Minimal Web App

```text
Backend API
Simple HTML dashboard
Basic authentication/session layer
Audit log viewer
```

The project does not require a real 5G core, Open5GS, free5GC, OAI, or O-RAN SC deployment. Those can be optional extensions.

---

## 10. Build Phase Requirements

Each team should submit:

1. Source code.
2. README with setup instructions.
3. API documentation.
4. Initial state examples.
5. At least five normal test cases.
6. At least five security test cases.
7. A hidden `CANARY_` value.
8. A short design note explaining how UE-to-gNB binding is enforced.

---

## 11. Break Phase Requirements

Each team should test at least two other teams’ applications.

For each confirmed vulnerability, students should submit a structured break report:

```markdown
## Break Report

### Target Team
Team name or app name.

### Vulnerability Title
Short descriptive title.

### Security Property Violated
P1 / P2 / P3 / P4 / P5 / P6.

### Attack Description
What request or sequence caused the issue?

### Expected Behavior
What should the application have done?

### Actual Behavior
What did the application do?

### Impact
What can an attacker achieve?

### Evidence
Request, response, screenshot, or log excerpt.

### Suggested Fix
How could the issue be prevented?
```

---

## 12. Fix Phase Requirements

Each team should patch their own application after receiving break reports.

The final fix report should include:

1. Summary of vulnerabilities found.
2. Root cause analysis.
3. Code-level or design-level fixes.
4. New regression tests.
5. Explanation of why the fix prevents the attack.
6. Remaining limitations.

---

## 13. Evaluation Criteria

Suggested grading:

| Component                             | Points |
| ------------------------------------- | -----: |
| Functional AMF state tracker          |     20 |
| Correct UE-to-gNB binding logic       |     20 |
| Security properties P1–P6             |     20 |
| Quality of break reports              |     15 |
| Quality of fixes and regression tests |     15 |
| README, documentation, and clarity    |     10 |

Total: 100 points.

---

## 14. Possible Extensions

Advanced students may extend the project in one of the following directions:

### Extension 1: Open5GS/free5GC Mapping

Map the toy API messages to real NGAP concepts and explain where similar state checks should exist in a real 5G core.

### Extension 2: AI-Assisted Fuzzing

Use an LLM or script-based fuzzer to generate malformed NGAP-like messages and test whether the AMF simulator handles them safely.

### Extension 3: O-RAN RIC Integration

Connect the AMF state tracker to a toy near-RT RIC dashboard that visualizes UE mobility and handover events.

### Extension 4: Formal State Machine

Define the UE lifecycle as a finite-state machine and verify that invalid transitions are rejected.

### Extension 5: Multi-Tenant Private 5G Scenario

Simulate multiple tenants or slices and require both gNB ownership and slice-level authorization.

---

## 15. Expected Outcome

By the end of the project, students should understand that many security vulnerabilities are not caused by missing cryptography alone. They often come from incorrect assumptions about state, ownership, and authorization.

The key lesson is:

> In 5G control-plane security, validating identifiers is not enough.
> The system must validate the relationship between the sender, the UE context, the serving gNB, and the current control-plane state.

N2Bind-Lite gives students a practical way to build, attack, and repair this class of vulnerability in a controlled educational environment.
