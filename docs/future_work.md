# Future work

Planned and candidate improvements, kept within the authorized-testing scope.

## Protocol / engine
- Full server transaction state machine (Timer G/H/I) for a richer UAS mode.
- Record-Route / loose-routing support for proxied topologies.
- PRACK (100rel), UPDATE, re-INVITE and SUBSCRIBE/NOTIFY flows.
- IPv6 targets and source binding.
- SCTP transport (where supported).

## Scenarios / SIPp compatibility
- More SIPp placeholders (`[last_*]`, `[field*]`, `[authentication]`).
- CSV "injection" data files for per-call values (bounded).
- A `convert` command that rewrites a simple SIPp scenario into the supported
  subset and reports required transformations.
- Assertions on arbitrary headers and bodies.

## Security tests
- Opt-in, rate-limited configurable test matrices (still bounded, still
  authorized-targets only).
- SDP/offer-answer validation and codec negotiation checks.
- TLS certificate chain / cipher inspection report.

## Reporting / UX
- HTML report with charts alongside JSON/CSV.
- Live progress bar and per-call tracing at `--verbose`.
- JUnit XML output for CI gating.
- Prometheus-style metrics export for long runs.

## Packaging / ops
- Signed Windows executable and an MSI installer.
- Config schema published as JSON Schema for editor validation.
- Optional Wireshark/tshark capture integration around a run.
