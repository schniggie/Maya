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
| `latest` | Built from `main` branch on every push |
| `v0.1.0` | Specific release version |
| `sha-abc1234` | Specific commit |

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

### Headless emulator

No phone is required for a dynamic smoke. `scripts/emulator_up.sh up` boots a headless AVD. `maya --emulator --package dvba_v1.1.0.apk` installs the APK, starts a matching frida-server, and injects `enumerate/loaded_classes`. Setup, KVM, and Apple Silicon notes are in [emulator.md](emulator.md). The optional GitHub workflow `.github/workflows/emulator-dynamic.yml` is manual or weekly and is not a pull-request check.

---

## Graceful Degradation

Maya is designed to work in reduced-capability modes:

| Component | Missing? | Behavior |
|-----------|----------|----------|
| Docker | Not installed | Dry-run mode — tools log what they would execute |
| LLM API key | Not set | Mock mode — deterministic responses for testing |
| Device | Not connected | `maya --static-only` still reports on an APK. The agent loop keeps planning dynamic steps it cannot run. |
| Frida server | Not running | Skips Frida-based instrumentation |
| Companion app | Not deployed | Falls back to ADB shell commands |

---

## CI/CD Pipeline

### GitHub Actions

Three workflows are configured:

**`ci.yml`** runs on every push and pull request to `main`:
- Ruff lint and format
- Pytest on Python 3.10, 3.11, and 3.12, including `maya --static-only` against the bundled DVBA APK
- An apktool decompile of that same APK
- The reusable static scan on `dvba_v1.1.0.apk` with `fail_on: none`
- Docker image build on pull requests, without pushing

**`maya-static-scan.yml`** is a reusable workflow. A caller passes `apk_path` and `fail_on`. It installs Maya from the workflow file's own commit, runs `maya --static-only`, and uploads `report.sarif`. `security-events: write` is set only on the upload job.

**`build-release.yml`** runs on `v*` tags and when dispatched by hand. It pushes `ghcr.io/<owner>/maya` and opens a GitHub Release for version tags.

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
