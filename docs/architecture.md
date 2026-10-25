# Architecture

SIPTestWin is layered so that transport, protocol, transaction, dialog and
scenario concerns stay independent and testable.

```
                 ┌─────────────────────────────────────────────┐
   CLI (Typer) ──▶│                  Engine                     │
                 │  per-call: build → send → match → assert     │
                 │  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
                 │  │ Scenario  │  │ Dialog    │ │ ClientTxn  │  │
                 │  │ steps     │  │ (ACK/BYE) │ │ (timers)   │  │
                 │  └───────────┘  └──────────┘  └───────────┘  │
                 │        │  builds/parses SIPMessage            │
                 └────────┼──────────────────────────┬──────────┘
                          ▼                           ▼
                   sip_message (RFC 3261)       Metrics / Reporting
                          │
                          ▼
                 Transport (UDP / TCP / TLS)  ◀──▶  Target SIP server
```

## Components

| Module | Responsibility |
| --- | --- |
| `sip_message` | Parse / build SIP requests and responses; headers multimap; branch, Call-ID and tag generation; SDP. |
| `transaction` | Client transaction state machine (RFC 3261 §17): matching by Via branch + CSeq method, timers T1/T2/B/F, UDP retransmission schedule. |
| `dialog` | Dialog/call state (RFC 3261 §12): Call-ID + tags, CSeq, remote target; builds in-dialog ACK and BYE. |
| `transport/` | Byte movers. `udp` (connectionless), `tcp` (stream framing by Content-Length, client + server), optional TLS. A `factory` builds client transports from config. |
| `authentication/` | Digest challenge parsing and response computation (RFC 2617; MD5, MD5-sess, qop=auth). Answers a single legitimate challenge — no guessing. |
| `scenario_parser` | SIPp-subset XML → typed `Send`/`Recv`/`Pause` steps with safe parsing (no DOCTYPE/entities) and bounded regex. |
| `config` | Dataclass model, YAML/JSON loading, strict validation and operational ceilings. |
| `safety` | Authorized-target allow-list, run limits, confirmation prompt, credential redaction, audit log. |
| `metrics` | Thread-safe counters, latency percentiles, failure reasons. |
| `reporting` | JSON/CSV writers and a Rich console summary; baseline loading. |
| `engine` | Orchestrates everything: paces and runs calls concurrently, routes inbound messages by Call-ID, drives steps, auto-handles Digest, records outcomes. |
| `security_tests/` | Protocol validation, controlled malformed-input catalog, regression comparison. |
| `testserver` | Local UAS simulator for loopback validation. |
| `cli` | Typer command surface. |

## Transaction vs. dialog

A **transaction** is one request plus its responses, matched by the Via
`branch` and CSeq method (e.g. the INVITE and its 100/180/200). A **dialog**
(call session) is the longer-lived relationship identified by Call-ID + local
and remote tags, spanning several transactions (INVITE→200→ACK … BYE→200).
The engine keeps these distinct: `ClientTransaction` tracks timers/matching
per request, while `Dialog` supplies correct tags/CSeq/target for ACK and BYE.

## Message flow (INVITE call)

1. Engine builds an INVITE (new Call-ID, From-tag, branch, CSeq, SDP body) and
   opens a client transaction.
2. Sends via the transport; on UDP, retransmits per T1 back-off until a
   response or Timer B.
3. Inbound datagrams are parsed and routed to the owning call by Call-ID.
4. 100/180 move the transaction to Proceeding; 200 establishes the `Dialog`.
5. Engine sends ACK (separate transaction) built from the dialog, pauses, then
   BYE; the 200 to BYE completes the call.
6. Metrics and a per-call record are recorded; reports are written at the end.

## Concurrency model

A single shared transport is used for all calls. Calls run on a thread pool
sized by `concurrency` and are launched at `call_rate`. Each call has its own
Call-ID and an inbox queue; the transport's receive thread parses and routes
messages to the right inbox. This keeps per-call logic sequential and simple
while supporting controlled parallel load.
