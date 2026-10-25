# Scenarios and SIPp compatibility

Scenarios are XML documents describing a UAC message flow. SIPTestWin
implements a **documented subset** of SIPp's scenario format plus a convenient
built-in request form.

## Elements

### `<scenario name="...">`
Root element. Must contain at least one step and start with a `<send>`.

### `<send>`
Two forms:

- **Built-in:** `<send request="OPTIONS"/>` — the engine constructs a
  well-formed request (OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL) from the
  identity/target configuration. ACK and BYE are built from the established
  dialog.
- **Template:** `<send><![CDATA[ ...raw SIP with [placeholders]... ]]></send>`
  — full control over the message. Lines may use `\n`; they are normalized to
  CRLF on the wire.

### `<recv>`
Waits for a matching message:
- `response="200"` — a response with that status code (100–699).
- `request="BYE"` — an inbound request of that method.
- `optional="true"` — if it does not arrive before timeout, continue anyway.
- `timeout="3000"` — per-step timeout in ms (otherwise `execution.timeout_seconds`).
- Contains optional `<action><ereg .../></action>` extractions.

### `<pause milliseconds="200"/>`
Waits the given time (interruptible by Ctrl+C).

### `<header>` / `<body>` inside a built-in `<send>`
Parametrize the message per step (built-in form only):

```xml
<send request="INVITE">
  <header name="Subject">Custom INVITE</header>      <!-- add / override -->
  <header name="X-Test-Id">[call_id]</header>        <!-- placeholders allowed -->
  <header name="Allow" action="remove"/>             <!-- remove a header -->
  <body content-type="application/sdp"><![CDATA[
v=0
...
]]></body>                                            <!-- replace the body -->
</send>
```

- `<header name="X">value</header>` adds or overrides header `X`.
- `<header name="X" action="remove"/>` strips header `X`.
- `<body content-type="...">...</body>` replaces the generated body; `Content-Length` is recomputed.
- Values support placeholders. See also the global `message` config section in
  [configuration.md](configuration.md). A ready example ships as
  `scenarios/invite_custom.xml`.

### `<action><ereg .../></action>`
Field extraction into a variable:
```xml
<ereg regexp="tag=([^;]+)" search_in="hdr" header="To" assign_to="remote_tag"/>
```
- `search_in` — `hdr` (a specific `header=`) or `msg` (whole message).
- `assign_to` — variable name, usable later as `[$remote_tag]` in templates.
- Regex is capped at 512 chars for safety.

## Placeholders (template form)

| Placeholder | Value |
| --- | --- |
| `[call_id]` | per-call Call-ID |
| `[branch]` | fresh RFC 3261 Via branch |
| `[cseq]` | current CSeq number |
| `[local_ip]` / `[local_port]` | source address |
| `[remote_ip]` / `[remote_port]` | target address |
| `[transport]` | UDP/TCP/TLS |
| `[from_user]` / `[from_domain]` / `[from_tag]` | identity |
| `[to_user]` / `[to_domain]` | identity |
| `[contact_user]` | identity |
| `[service]` | alias for `[to_user]` |
| `[$name]` | a variable extracted by `<ereg>` |

## Authentication in scenarios

When `security.authentication=digest`, a 401/407 challenge is answered
automatically with the configured lab credentials; the authenticated retry is
re-sent and the scenario continues. You can either wait directly for the final
code (`recv response="200"`) or observe the challenge explicitly
(`recv response="401" optional="true"` then `recv response="200"`).

## SIPp compatibility matrix

| SIPp feature | Status | Notes |
| --- | --- | --- |
| `<send>` with raw message + placeholders | **Supported** | Subset of keywords (see table above). |
| `<recv response=...>` / `request=...` | **Supported** | |
| `optional`, `timeout` on `recv` | **Supported** | |
| `<pause>` | **Supported** | `milliseconds` (or `ms`). |
| `<ereg>` extraction into variables | **Partial** | `regexp`, `search_in`, `header`, `assign_to`, `occurence`; bounded regex. |
| Response-code validation / success-failure | **Supported** | via `recv response` and assertions. |
| Digest auth | **Supported** | Auto-answered; MD5/MD5-sess, qop=auth. |
| `[last_*]`, `[field*]`, full keyword set | **Partial** | Only the documented placeholders. |
| `<nop>`, `<Reference>` | **Tolerated** | Parsed as no-ops. |
| `sendCmd` / `recvCmd` (external process control) | **Not supported** | Rejected for safety. |
| 3PCC / media (RTP) / `rtp_echo` | **Not supported** | SIP signalling only. |
| CSV injection / `-inf` data files | **Not supported** | Use `calls` + per-call identifiers. |
| Unbounded rate / flood modes | **Not supported** | Hard ceilings enforced. |

## Converting a simple SIPp scenario

1. Replace unsupported keywords/placeholders with the documented subset.
2. Remove any `sendCmd`/`recvCmd`, 3PCC and media directives.
3. Validate: `siptestwin validate-scenario --file your.xml`.
4. Dry-run in simulate mode before any active run.
