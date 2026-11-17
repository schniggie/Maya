# Building & Infrastructure

This guide covers how to build Maya from source, the Docker sandbox architecture, host setup, and infrastructure decisions.

---

## Building from Source

### Prerequisites

| Dependency | Version | Required |
|-----------|---------|----------|
| Python | 3.10+ | Yes |
| Docker Desktop | Latest | For sandbox execution (optional — dry-run mode works without it) |
| ADB | Latest | For Android device testing |
| Git | Latest | For cloning |

### Install

```bash
git clone https://github.com/schniggie/Maya.git
cd Maya

# Create virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1

# Install Maya + dev dependencies
pip install -e ".[dev]"
```

Or use the bootstrap script:

```bash
./scripts/install.sh
```

This creates a venv, installs the package in editable mode, and runs `setup-host.sh`.

### Verify Installation

```bash
# Check CLI works
maya --help

# Run tests
pytest -q

# List available skills
maya --list-skills
```

---

## Docker Sandbox

### Why Docker?

Every Maya agent gets its own Docker container (sandbox). This provides:

- **Isolation** — Dangerous tool execution (Frida, SQLMap, Nuclei, shell commands) never runs on your host
- **Reproducibility** — Same toolchain on every machine
- **Cleanup** — Containers are destroyed after the scan; nothing persists
- **Security** — Even if an exploit payload goes wrong, it's contained

### The Sandbox Image

The image is defined in `containers/Dockerfile.sandbox` and based on **Kali Linux Rolling**:

```
Base: kalilinux/kali-rolling
├── Python 3 + venv at /opt/maya-venv
├── System tools: git, curl, wget, jq, sqlite3, nmap, tcpdump, ffuf, binwalk, file
├── Java: default-jdk
├── Android: adb, apktool, jadx, dex2jar
├── Go tools: nuclei, httpx (ProjectDiscovery)
├── Python tools: frida-tools, objection, mitmproxy, semgrep, reflutter, cryptography
├── Node.js / npm
├── Ruby (full)
├── Caido CLI (best-effort install)
└── Maya agent package itself
```

### Building the Image

```bash
# From project root
docker build -f containers/Dockerfile.sandbox -t maya:latest .
```

> **Note**: The build takes 10-20 minutes on first run due to the large toolchain. Subsequent builds use Docker layer caching.

### Pulling from GHCR

```bash
docker pull ghcr.io/schniggie/maya:latest
```

### Image Tags

| Tag | Description |
|-----|-------------|
| `latest` | Published on a version tag or a manual run of the release workflow |
| `v0.1.0` | Release tag |
| `0.1` | Major.minor tag |

### Running the Image Standalone

```bash
docker run --rm -it \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v /path/to/app.apk:/data/app.apk \
  maya:latest \
  --target com.example.app --package /data/app.apk -n
```

### How the Sandbox Works at Runtime

```
Host Machine
  │
  ├── Maya CLI process (maya/main.py)
  │     │
  │     ├── Spawns DockerRuntime
  │     │     ├── docker run maya:latest
  │     │     ├── Mounts /app workspace
  │     │     └── Starts tool_server (FastAPI on port 8000)
  │     │
  │     ├── Agent sends tool calls via HTTP to sandbox
  │     │     POST http://sandbox:8000/execute
  │     │     {"tool": "terminal_execute", "args": {"command": "apktool d app.apk"}}
  │     │
  │     └── Sandbox executes and returns result
  │           {"status": "ok", "stdout": "...", "exit_code": 0}
  │
  └── ADB (forwarded to device)
```

Tools marked with `sandbox_execution=True` are routed to the container's FastAPI server. Tools marked `sandbox_execution=False` run on the host (e.g., device bridge commands that need ADB access).

---

## Host Setup

The `scripts/setup-host.sh` script prepares the host for device communication:

```bash
./scripts/setup-host.sh
```

What it does:
1. Starts the ADB server
2. Lists connected devices
3. Forwards port `27042` (Frida default)
4. Forwards port `9999` (companion app)
5. Reverses port `8080` (proxy traffic from device to host)
6. Attempts to start `frida-server` on the device via `su`

### Manual Port Setup

```bash
# Frida
adb forward tcp:27042 tcp:27042

# Companion app
adb forward tcp:9999 tcp:9999

# Proxy (device → host)
adb reverse tcp:8080 tcp:8080

# Start frida-server (rooted device)
adb shell "su -c '/data/local/tmp/frida-server -D'"
```

---

## Graceful Degradation

Maya is designed to work in reduced-capability modes:

| Component | Missing? | Behavior |
|-----------|----------|----------|
| Docker | Not installed | Dry-run mode — tools log what they would execute |
| LLM API key | Not set | Mock mode — deterministic responses for testing |
| Device | Not connected | Static-only analysis — no dynamic tools |
| Frida server | Not running | Skips Frida-based instrumentation |
| Companion app | Not deployed | Falls back to ADB shell commands |

---

## CI/CD Pipeline

### GitHub Actions

**`ci.yml`** — Runs on every push and pull request to `main`:
- Ruff lint and format
- Unit tests on Python 3.10, 3.11, and 3.12 (`pytest -m "not integration and not smoke"`)
- DVBA static smoke, including the static gate, when `apktool` is installed
- The reusable static-gate workflow against `dvba_v1.1.0.apk` with `--fail-on none` (the lab app is expected to have findings; this job checks that the workflow runs)
- Docker image build on pull requests, without pushing

**`maya-static-gate.yml`** — Reusable workflow and manual dispatch. Decompiles an APK and writes `report.json`, `report.md`, and `report.sarif`. Exit 1 when a finding meets `fail_on`. See the [README](../README.md#device-free-static-gate-no-llm-no-device).

**`build-release.yml`** — Runs on `v*` tags and manual dispatch:
- Build and push `ghcr.io/<owner>/maya` (`latest` on a tag or a manual run)
- GitHub Release on `v*` tags

There is no CodeQL workflow, Dependabot config, or SBOM step in this repository.

---

## Infrastructure Diagram

```
┌──────────────────────────────────────────────────────┐
│                    Host Machine                       │
│                                                       │
│  ┌───────────────┐    ┌────────────────────────────┐ │
│  │   Maya CLI    │    │  Docker Sandbox (Kali)      │ │
│  │  maya/main.py │───►│  tool_server :8000          │ │
│  │               │    │  ├── apktool, jadx          │ │
│  │  Agent Loop   │    │  ├── frida-tools            │ │
│  │  LLM Client   │    │  ├── nuclei, semgrep        │ │
│  │  Telemetry    │    │  ├── sqlmap, nmap            │ │
│  └───────┬───────┘    │  └── python, node, go, ruby │ │
│          │            └────────────────────────────┘ │
│          │ ADB                                        │
│          ▼                                            │
│  ┌───────────────┐                                   │
│  │ Android Device│  ┌──────────────────┐             │
│  │  :9999 Comp.  │  │  LLM Provider    │             │
│  │  :27042 Frida │  │  (OpenAI/Claude/ │             │
│  └───────────────┘  │   Ollama/etc.)   │             │
│                      └──────────────────┘             │
└──────────────────────────────────────────────────────┘
```
