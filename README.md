# SIPTestWin

A professional, SIPp-inspired **SIP testing tool for Windows 10 / 11**. It runs
authorized interoperability, protocol-conformance, controlled-load and
robustness tests against SIP servers directly from PowerShell, CMD or CI — no
WSL and no Linux VM required.

> **Authorized use only.** SIPTestWin is for systems you own or are explicitly
> authorized to test. It enforces an explicit allow-list of targets, rate /
> concurrency / duration ceilings, a validation-only default mode, explicit
> confirmation before any active test, credential redaction and an audit log.
> It contains **no** credential brute-forcing, unbounded flooding, toll-fraud,
> or automated third-party exploitation features, by design.

## Features

- SIP engine with explicit **transaction** and **dialog** state machines,
  timers and UDP retransmissions (RFC 3261).
- Methods: OPTIONS, REGISTER, INVITE, ACK, CANCEL, BYE; provisional/final
  responses; **Digest** authentication (auto-answered from lab credentials).
- Transports: **UDP**, **TCP**, and optional **TLS**.
- **SIPp-compatible XML scenario** subset (`send` / `recv` / `pause`, variable
  extraction via `ereg`, placeholders) plus a convenient built-in request form.
- YAML / JSON configuration with strict validation.
- Metrics: messages, response categories, latency p50/p95/p99, transactions,
  timeouts, transport errors, calls attempted/established/terminated, failure
  reasons — distinguishing **server failures** from **local generator errors**.
- JSON + CSV reports and a readable console summary.
- **SIP message tracing / capture**: console ladder, a human-readable
  `.trace.log`, and a **Wireshark-openable `.pcap`** (no tshark/npcap needed).
- **Source-IP selection**: `siptestwin interfaces` lists the local IPs; pick one
  with `--local-host` or set it manually.
- A built-in **local test SIP server** so you can validate everything on
  loopback with no external system.
- Security-test modules: protocol validation, controlled malformed-input
  catalog, regression comparison.
- Packaged as a standalone `.exe` with PyInstaller.

## Quick start (Windows PowerShell)

```powershell
py -m venv C:\Users\you\.venvs\siptestwin
C:\Users\you\.venvs\siptestwin\Scripts\Activate.ps1
pip install -e .

# 1. Diagnose the environment
siptestwin doctor

# 2. In one terminal, start the local loopback test server
siptestwin testserver --port 55060

# 3. In another terminal, validate then run (SIMULATE is the default)
siptestwin validate-config  --config config\example.yaml
siptestwin validate-scenario --file scenarios\basic_call.xml
siptestwin run --config config\example.yaml --scenario scenarios\basic_call.xml --host 127.0.0.1 --port 55060

# 4. Run for real (transmits packets) against the authorized loopback target
siptestwin run --config config\example.yaml --scenario scenarios\basic_call.xml --host 127.0.0.1 --port 55060 --execute

# 5. List your local IPs, and capture the SIP traffic to a Wireshark pcap
siptestwin interfaces
siptestwin run --config config\example.yaml --scenario scenarios\basic_call.xml --host 127.0.0.1 --port 55060 --execute --trace-console --pcap --trace-file results\mytrace
```

`run` is **simulate-only** unless you pass `--execute`, and an active run against
a target not listed in `security.authorized_targets` is refused.

## Documentation

- [docs/architecture.md](docs/architecture.md) — components and message flow
- [docs/configuration.md](docs/configuration.md) — every config field and CLI override
- [docs/scenarios.md](docs/scenarios.md) — scenario format and SIPp compatibility matrix
- [docs/security.md](docs/security.md) — safety model and responsible-use policy
- [docs/windows_build.md](docs/windows_build.md) — venv, tests, PyInstaller, troubleshooting

## Project layout

```
siptestwin/
├── pyproject.toml          requirements.lock.txt
├── config/example.yaml
├── scenarios/*.xml
├── src/siptestwin/         engine, sip_message, transaction, dialog,
│                           transport/, authentication/, security_tests/,
│                           config, safety, metrics, reporting, cli, testserver
├── tests/{unit,integration}
└── docs/
```

## License

MIT. Use responsibly and only where authorized.
