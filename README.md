# Maya

**Autonomous AI-Powered Mobile Security Agent for Android & iOS**

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![CI](https://github.com/schniggie/Maya/actions/workflows/ci.yml/badge.svg)](https://github.com/schniggie/Maya/actions/workflows/ci.yml)

Autonomous security testing agent for mobile apps. Point it at an APK/IPA, provide an LLM API key, and it runs static analysis, dynamic instrumentation, and exploit chaining automatically.

> Maintained fork of [C0oki3s/Maya](https://github.com/C0oki3s/Maya). Upstream appears inactive; this repo is the living base for continued work.

## Quick Start

### Option 1: Docker (Easiest - No Setup)

```bash
docker run --rm -it \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v /path/to/app.apk:/data/app.apk \
  ghcr.io/schniggie/maya:latest \
  --target com.example.app --package /data/app.apk -n
```

Replace `OPENAI_API_KEY` with your key or use `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.

Image tags are published from this fork on version tags via `.github/workflows/build-release.yml`.

### Option 2: Local Installation

```bash
git clone https://github.com/schniggie/Maya.git && cd Maya
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

export OPENAI_API_KEY="sk-..."
maya --target com.example.app --package app.apk --device SERIAL
```

**iOS:**
```bash
maya --target com.example.app --package app.ipa --device UDID
```

## Usage

```bash
maya --target PACKAGE_NAME --package PATH_TO_APK_OR_IPA [--device SERIAL] [OPTIONS]
```

### Common Options

| Flag | Purpose |
|------|---------|
| `--target` | Package name (required) |
| `--package` | Path to APK or IPA (required) |
| `--device` | Device serial / iOS UDID |
| `--scan-mode quick\|standard\|comprehensive` | Analysis depth (default: comprehensive) |
| `-n, --non-interactive` | Headless mode |
| `--list-skills` | List loaded skill packs |
| `--model` | LLM: `openai/gpt-4o`, `anthropic/claude-sonnet-4-20250514`, etc. |
| `--api-key` | LLM API key (override env var) |
| `--static-only` | Scan an APK with no LLM, device, or apktool |
| `--fail-on none\|low\|medium\|high\|critical` | With `--static-only`, exit 1 at this severity or above (default: `none`) |
| `--output-dir` | Report directory. `--static-only` writes json, markdown, html, and SARIF |
| `--emulator` | Boot a headless Android emulator, install the APK, start frida-server, smoke one `enumerate/` script, then tear it down. No LLM |
| `--avd-api`, `--avd-abi`, `--avd-device`, `--avd-name` | Emulator API, ABI, profile, and AVD name. Defaults: 34, host ABI, `pixel_6`, `maya` |
| `--frida-version` | frida-server release to push. Default: installed `frida`, then `16.7.19` |
| `--smoke-script` | Enumerate script for `--emulator` (default `enumerate/loaded_classes`) |
| `--keep-emulator` | Leave the AVD running after `--emulator` |

### Examples

```bash
# Quick static analysis
maya --target com.app --package app.apk --scan-mode quick

# Full scan with custom LLM
maya --target com.app --package app.apk --model anthropic/claude-sonnet-4-20250514 --api-key sk-ant-...

# Resume interrupted scan
maya --target com.app --resume com.app

# List skills
maya --list-skills
```

### Device-free static scan

`maya --static-only` reads an APK without an LLM, a device, or apktool. It writes `report.json`, `report.md`, `report.html`, and `report.sarif` (SARIF 2.1.0).

```bash
maya --static-only --package app.apk --output-dir maya_runs/app
maya --static-only --package app.apk --fail-on high
```

`--fail-on` defaults to `none`. Exit `1` when a finding is at or above the threshold, and exit `2` when the APK cannot be scanned.

The repo bundles Damn Vulnerable Bank for that path:

```bash
maya --static-only --package dvba_v1.1.0.apk -n
pytest -q tests/test_static_scan.py
```

Run that scan on every APK from GitHub Actions with [`.github/workflows/maya-static-scan.yml`](.github/workflows/maya-static-scan.yml). The workflow installs Maya from its own commit and uploads `report.sarif`. `security-events: write` belongs on the calling job, which is the only place this repo's CI grants it.

```yaml
jobs:
  maya:
    permissions:
      contents: read
      actions: write
      security-events: write
    uses: schniggie/Maya/.github/workflows/maya-static-scan.yml@main
    with:
      apk_path: app/build/outputs/apk/release/app-release.apk
      fail_on: high
```

This repo calls the same workflow on `dvba_v1.1.0.apk` with `fail_on: none`, so the lab APK does not fail CI.

An additional apktool decompile of the same APK is available when you want the decoded tree:

```bash
python scripts/smoke_dvba_static.py   # requires apktool
pytest -q -m smoke
```

### Frida script library

Shipped scripts live in `assets/frida-scripts/<category>/<name>.js`. The loader resolves a name such as `enumerate/loaded_classes` (or a unique file stem), checks that the file stays inside a script root and is readable UTF-8, and injects that one script through the existing `frida_run_script` path.

```python
from maya.tools.frida_scripts import list_scripts, load_script
from maya.tools.frida_tool import frida_run_named_script

list_scripts()
load_script("enumerate/loaded_classes")
frida_run_named_script("com.example.app", "enumerate/loaded_classes")
```

`frida_list_scripts` is the same catalog for the agent. `MAYA_FRIDA_SCRIPTS` is an extra directory and overrides a bundled name when both exist. `~/.maya/frida-scripts/` is included when that directory exists and the env var is unset. Inside the sandbox image the bundled copy is `/opt/maya-assets/frida-scripts`.

Every bundled script is self-contained. `frida_run_script` injects one file, so the message helper is copied into each script rather than loaded from a shared module. Scripts report with `send({ tag, event, data })` and mirror that object as one JSON line on stdout. `tag` is the script stem, `event` is `ready`, `hook`, `hit`, `miss`, `error`, or `done`, and `data` is a plain object. The first `//` line is the catalog description. See `assets/frida-scripts/README.md`. The `exploit/` scripts observe WebView settings, deeplink parameters, and content-provider calls the app already makes. They do not inject script, send intents, or query providers on their own.

`frida_generate_hook` writes one more script in that same shape for a class and method you name. The goal is observation (`log_arguments`, `log_return`, `trace_calls`, `dump_field`, `time_call`) or a detection bypass already covered by `bypass/` (`ssl_pinning`, `root`, `debug`, `emulator`, `rasp`). The tool checks the script before it is saved or handed to `frida_run_script`, and it refuses forge, injection, intent, provider, exfiltration, and native-patch requests. Details are in [docs/frida-hook-generation.md](docs/frida-hook-generation.md).

### Companion client

`companion_app_command` talks to the Android companion over HTTP. `COMPANION_HTTP_URL` defaults to `http://127.0.0.1:9999/command`. The client calls `GET /health` before `POST /command`, retries connection failures with backoff, and returns an error dict when the companion or device is absent. It does not raise. `COMPANION_ATTEMPTS` (1–5, default 3), `COMPANION_CONNECT_TIMEOUT` (default 2 seconds), and `COMPANION_BACKOFF_SECONDS` (default 0.2) tune that behavior. A read timeout on the command itself is returned immediately so the same command is not sent twice. A websocket is used only when `COMPANION_WS_URL` is set, and a websocket failure falls back to HTTP.

### Headless emulator

`maya --emulator` runs the dynamic path against a headless Android emulator. It does not use an LLM, and it is separate from `--static-only`. The smoke installs the APK, starts a matching `frida-server`, checks the Frida catalog and the companion client, injects one `enumerate/` script (`enumerate/loaded_classes` by default), and tears the emulator down.

```bash
pip install -e ".[dynamic]"    # frida==16.7.19 and frida-tools==13.6.1
maya --emulator --package dvba_v1.1.0.apk
scripts/emulator_up.sh up      # boot only; leave the AVD running
scripts/emulator_up.sh down
```

A missing Android SDK, `adb`, or `adb root` prints an error and exits 2. Prerequisites, KVM, and Apple Silicon notes are in [docs/emulator.md](docs/emulator.md). The bundled lab target is Damn Vulnerable Bank, package `com.app.damnvulnerablebank`.

[`.github/workflows/emulator-dynamic.yml`](.github/workflows/emulator-dynamic.yml) is an optional manual or weekly job. It is not part of `ci.yml` and does not gate pull requests. The default CI suite stays device-free.

## LLM Configuration

### Environment Variables

Set any of these to configure your LLM:

```bash
# Model and API key
export MAYA_LLM="gpt-4o"                    # Model string (required)
export LLM_API_KEY="sk-..."                 # API key for the provider
export LLM_API_BASE="http://localhost:1234/v1"  # API base URL (optional, for self-hosted)
export MAYA_REASONING_EFFORT="high"         # Optional: high/medium/low
```

### Supported Providers

Maya uses **LiteLLM**, which supports **100+ LLM providers** (OpenAI, Anthropic, Google, Groq, Ollama, LM Studio, Azure, and more).

See [LiteLLM supported models](https://docs.litellm.ai/docs/providers) for the complete list and model strings.

### Config File

Or create `~/.maya/config.json`:

```json
{
  "model": "gpt-4o",
  "api_key": "sk-...",
  "api_base": "http://localhost:1234/v1",
  "temperature": 0.1,
  "max_tokens": 8192,
  "reasoning_effort": "high"
}
```

### Priority Order

1. **CLI flags** (highest): `--model gpt-4o --api-key sk-...`
2. **Environment variables**: `export MAYA_LLM="gpt-4o"`
3. **Config file** `~/.maya/config.json` (lowest)

## Results

Reports saved to `maya_runs/<package_name>/`:

```
report.json       # Machine-readable findings
report.md         # Human-readable summary
report.html       # Styled HTML report
report.sarif      # SARIF 2.1.0 from --static-only
events.jsonl      # Full telemetry stream
```

## Skill packs

Skills are Markdown playbooks under `maya/skills/`. The loader picks up every `*.md` file in a category directory. These target packs are verification checklists:

| Skill | Category | Use when |
| --- | --- | --- |
| `fintech_mobile_banking` | `targets/` | Banking, wallet, and payment apps |
| `flutter_apps` | `frameworks/` | The package embeds Flutter (`libflutter.so`, `libapp.so`) |
| `owasp_masvs` | `standards/` | Map findings to MASVS v2 control groups |

`flutter_analysis` is still the Flutter tool workflow. `flutter_apps` is the assessment checklist.

```bash
maya --list-skills
maya --target com.example.bank --package app.apk --skills fintech_mobile_banking,owasp_masvs
maya --target com.example.app --package app.apk --skills flutter_apps,flutter_analysis
```

## Development

```bash
pip install -e ".[dev]"
pytest -q -m "not integration and not smoke"   # unit tests, including --static-only on DVBA
pytest -q tests/test_cli_wrappers.py tests/test_agent_decisions.py tests/test_frida_script_library.py tests/test_companion_client.py tests/test_emulator.py tests/test_headless_dynamic.py
pytest -q -m smoke                             # apktool decompile of DVBA
ruff check . && ruff format .                  # Lint & format
```

`test_cli_wrappers.py` and `test_agent_decisions.py` mock subprocess and the LLM. `test_frida_script_library.py` and `test_companion_client.py` mock the process runner, filesystem, and HTTP session. `test_emulator.py` and `test_headless_dynamic.py` mock the SDK, adb, and frida-server download. They are part of the default unit suite (`not integration and not smoke`) and do not need a device, Frida server, or an API key. Device-gated tests stay marked `integration`; the apktool DVBA check stays marked `smoke`. A live emulator boot is `pytest -q -m integration` with `MAYA_EMULATOR_INTEGRATION=1`.

## Documentation

- [LLM Configuration](docs/llm-configuration.md) — All provider options
- [Building & Infrastructure](docs/building-and-infrastructure.md) — Docker & host setup
- [Roadmap](docs/ROADMAP.md) — Planned features
- [Contributing](CONTRIBUTING.md) — How to contribute

## License

MIT
