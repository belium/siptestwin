# Windows install, build and troubleshooting

Tested on Windows 11 with Python 3.14 (requires 3.12+). No WSL or Linux VM is
needed.

## 1. Create a virtual environment

Keep the venv outside any cloud-synced folder (e.g. OneDrive) to avoid file
locks:

```powershell
py -m venv C:\Users\you\.venvs\siptestwin
C:\Users\you\.venvs\siptestwin\Scripts\Activate.ps1
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## 2. Install dependencies

```powershell
pip install --upgrade pip
pip install -e .            # runtime deps from pyproject
pip install -e ".[dev]"     # plus pytest and pyinstaller
```

For a reproducible install, pin to the tested versions:

```powershell
pip install -r requirements.lock.txt
```

Expected: `siptestwin version` prints `SIPTestWin 0.1.0 (python 3.x.y)`.

## 3. Run the tests

```powershell
pytest -q
```

Expected tail (counts may grow):

```
41 passed in ~11s
```

Integration tests start the loopback test server automatically; they bind only
to `127.0.0.1`.

## 4. Run a lab scenario

```powershell
# terminal 1
siptestwin testserver --port 55060

# terminal 2
siptestwin run -c config\example.yaml --scenario scenarios\basic_call.xml `
  --host 127.0.0.1 --port 55060 --calls 3 --execute
```

Expected: a Rich summary with `Passed = 3`, responses `1xx`/`2xx`, and report
files under `results\`. See `docs/example_report.json` for a sample.

## 5. Build a standalone .exe (PyInstaller)

```powershell
pip install pyinstaller
pyinstaller --onefile --name siptestwin ^
  --collect-submodules siptestwin ^
  --paths src ^
  src\siptestwin\__main__.py
```

The executable is written to `dist\siptestwin.exe`. Smoke test:

```powershell
dist\siptestwin.exe version
dist\siptestwin.exe doctor
```

> If `--onefile` startup is slow or AV-flagged, use `--onedir` instead and
> distribute the whole `dist\siptestwin\` folder.

## 6. Distribute without Python

Ship `dist\siptestwin.exe` (onefile) or the `dist\siptestwin\` folder (onedir)
together with your `config\*.yaml` and `scenarios\*.xml`. The target machine
needs no Python installation.

## 7. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `recv` times out on a real target | Windows Defender Firewall is dropping inbound SIP responses. Allow `python.exe`/`siptestwin.exe` for the active network profile, or test against `testserver` first. |
| `authorization error` on run | Add the target to `security.authorized_targets` (or `--authorize`). |
| `UDP bind failed` | Another process holds the port; use `local_port: 0` for an ephemeral source port. |
| TLS verification errors | For a lab cert set `security.verify_tls: false` (only in a trusted lab). |
| `ModuleNotFoundError: siptestwin` | Activate the venv and `pip install -e .`. |
| Slow/blocked `.exe` | Use `--onedir`; add an AV exclusion for the build output in your lab. |
| High latency numbers | Expected under high `concurrency` on one host; lower `call_rate`/`concurrency`. |

## 8. `doctor`

`siptestwin doctor` checks the Python version, required imports and UDP bind,
and prints firewall/port guidance. Use it first on any new machine.
