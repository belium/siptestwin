# Security model and responsible use

SIPTestWin is built for **authorized** testing of SIP infrastructure you own or
have explicit written permission to assess (interoperability, conformance,
controlled load and robustness). The safety controls below are part of the
tool's contract, not optional add-ons.

## Authorization

- **Explicit allow-list.** An active run is refused unless `target.host`
  matches `security.authorized_targets` (hostnames, IPs or CIDRs). An empty
  allow-list authorizes nothing.
- **No implicit trust.** A private/RFC1918 address is *not* treated as
  authorization. You must list it.
- Hostnames are resolved and checked against the list, so a name and its IP are
  both acceptable entries.

## Bounded execution

- `calls`, `concurrency`, `call_rate` and `duration_seconds` are validated and
  additionally capped by hard ceilings (100000 / 500 / 500 per s / 86400 s).
- A single over-length message or scenario/XML document is rejected (64 KiB and
  1 MiB caps respectively).
- Ctrl+C stops the run immediately and still writes a partial report.

## Modes

- **Simulate (default).** `run` builds and validates every message but
  transmits nothing. Use it to verify scenarios and configuration safely.
- **Active.** `--execute` transmits. Before starting, the tool prints the
  target, transport, scenario and limits and requires confirmation (unless
  `--yes`).

## Credential handling

- Only a single, legitimate Digest challenge is answered, using credentials you
  configured for a lab account. There is **no** credential guessing or
  brute-force capability.
- Passwords are removed from config dumps, logs and reports
  (`Authorization`/`Proxy-Authorization` and `response=` are redacted).
- Prefer lab-only credentials; never put production secrets in a config file.

## Audit log

Every active run appends JSON lines to `<output_dir>/audit.log`
(`run_start`/`run_end` with target, scenario, limits and pass/fail counts),
redacted of credentials.

## Robustness testing

The malformed-input catalog (`security_tests/malformed.py`) is a **fixed, small
set** of individually malformed requests (missing Call-ID, CSeq mismatch, Via
without branch, negative Max-Forwards, overstated Content-Length, duplicate
From). It checks that a server rejects them gracefully (typically 4xx) rather
than crashing. It is not a fuzzer and does not operate at volume.

## Explicitly out of scope

SIPTestWin intentionally does **not** implement, and will not be extended to
implement:

- credential brute-forcing or password spraying;
- unbounded flooding / denial-of-service traffic generation;
- toll fraud or unauthorized call origination;
- evasion of security controls;
- automated exploitation against third parties.

## XML/YAML safety

Scenario XML is parsed with DOCTYPE and entity declarations rejected (no XXE /
billion-laughs), and embedded regular expressions are length-limited.
Configuration YAML is loaded with `yaml.safe_load` (no arbitrary object
construction).

## Your responsibilities

- Obtain written authorization before testing any system you do not own.
- Keep tests within agreed windows, rates and scopes.
- Treat captured data and credentials as sensitive.
