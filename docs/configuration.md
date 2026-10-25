# Configuration

Configuration is YAML or JSON. Every operational parameter lives here, so no
code changes are needed to run a different test. All fields are validated:
types, ranges and incompatible combinations are rejected, and the target must
be explicit.

## Sections and fields

### `target` (required)
| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `host` | string | — | SIP server under test. Required. |
| `port` | int 1–65535 | 5060 | |
| `transport` | `udp`/`tcp`/`tls` | `udp` | |

### `identity`
| Field | Type | Default |
| --- | --- | --- |
| `from_user` | string | `tester` |
| `from_domain` | string | `lab.example` |
| `to_user` | string | `1001` |
| `to_domain` | string | target host |
| `contact_user` | string | `tester` |
| `display_name` | string | — |

### `execution`
| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `scenario` | path | — | Required. |
| `calls` | int 1–100000 | 1 | Total scenario executions. |
| `concurrency` | int 1–500 | 1 | ≤ `calls`. |
| `call_rate` | float >0 ≤500 | 1.0 | Launches per second. |
| `timeout_seconds` | float >0 | 5 | Per `recv` wait. |
| `duration_seconds` | float 0–86400 | 0 | 0 = bounded by `calls`. |
| `local_host` | string | autodetected | Via/Contact host. |
| `local_port` | int | 0 | 0 = ephemeral source port. |

### `security`
| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `authentication` | `disabled`/`digest` | `disabled` | |
| `username` | string | — | Required for digest. |
| `password` | string | — | Lab credentials only; redacted from logs/reports. |
| `verify_tls` | bool | true | |
| `authorized_targets` | list | `[]` | Hostnames, IPs or CIDRs. **Empty authorizes nothing.** |
| `require_confirmation` | bool | true | |

### `reporting`
| Field | Type | Default |
| --- | --- | --- |
| `output_dir` | path | `results` |
| `formats` | list of `json`/`csv` | `[json]` |

### `message` (optional)
Parametrizes built-in requests and the INVITE body/headers. Header values
support scenario placeholders (`[call_id]`, `[local_ip]`, `[$var]`, …).

| Field | Description |
| --- | --- |
| `extra_headers` | Map of headers added to every built-in request. |
| `remove_headers` | List of headers stripped from every built-in request. |
| `invite.content_type` | Content-Type for the INVITE body (default `application/sdp`). |
| `invite.sdp` | Custom SDP body (overrides the generated one). |
| `invite.extra_headers` | Headers added only to INVITE. |

```yaml
message:
  extra_headers:
    Subject: "SIPTestWin test"
    X-Lab: "ci-run-42"
  remove_headers:
    - "User-Agent"
  invite:
    extra_headers:
      Priority: "urgent"
    sdp: |
      v=0
      o=siptestwin 0 0 IN IP4 [local_ip]
      s=Custom Session
      c=IN IP4 [local_ip]
      t=0 0
      m=audio 40000 RTP/AVP 0
      a=rtpmap:0 PCMU/8000
      a=sendrecv
```

Per-step overrides (a scenario `<send>`'s `<header>`/`<body>`) take precedence
over these global values. See [scenarios.md](scenarios.md).

### `capture` (optional)
Trace / capture every SIP message sent and received.

| Field | Default | Notes |
| --- | --- | --- |
| `enabled` | false | Master switch. |
| `console` | false | One line per message to the console. |
| `console_full` | false | Also print the full message. |
| `text` | true | Write `<file>.trace.log` (human-readable, credential hashes redacted). |
| `pcap` | false | Write `<file>.pcap`, openable in Wireshark (no tshark needed). |
| `file` | null | Base path; default `<output_dir>/trace-<timestamp>`. |

```yaml
capture:
  enabled: true
  console: true
  pcap: true
  file: "results/mytrace"     # -> results/mytrace.trace.log + results/mytrace.pcap
```

Equivalent `run` flags (override the config): `--capture` (text log), `--pcap`,
`--trace-console`, `--trace-full`, `--trace-file <base>`.

## Choosing the source IP

`execution.local_host` sets the source IP used in Via/Contact and for binding.
List the IPs available on this machine and pick one:

```powershell
siptestwin interfaces
siptestwin run -c config\example.yaml --local-host 192.168.1.26 ...
```

Leave it unset to auto-detect the default-route IP, or set it manually (in the
config or with `--local-host`).

## Operational ceilings

Independent of config, the tool caps `calls` (100000), `concurrency` (500),
`call_rate` (500/s) and `duration_seconds` (86400). The effective run uses the
minimum of your config and these ceilings.

## CLI overrides

`run` accepts flags that override config fields with the same validation:

```
--host --port --transport --scenario --calls --concurrency --call-rate
--output-dir --authorize <host|cidr>   (repeatable)
--execute   (send packets; default is simulate)
--yes       (skip the active-run confirmation)
```

Example:

```powershell
siptestwin run -c config\example.yaml --host 192.0.2.10 --transport tcp `
  --calls 50 --concurrency 5 --call-rate 10 --authorize 192.0.2.0/24 --execute
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (all calls passed, or simulate completed). |
| 1 | Aborted by user / nothing to do. |
| 2 | Invalid configuration or scenario. |
| 3 | Target not authorized. |
| 4 | Run completed but one or more calls failed. |
