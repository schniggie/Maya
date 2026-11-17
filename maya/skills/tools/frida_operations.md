---
name: frida_operations
description: Frida runtime instrumentation operations, prerequisites, and troubleshooting
category: tools
version: "2.1"
last_updated: "2026-11-17"
frida_version_tested: "16.5.x"
applies_to: [dynamic, api, exploit]
platform: [android, ios]
---

# Frida Operations Guide

## Prerequisites - Check Before Every Frida Operation

Before ANY Frida tool call, verify the following:

1. **Client version**: `terminal_execute(command="frida --version")`
   - Must match frida-server major.minor version on device
   - Mismatch causes: silent failures, crashes, "unable to communicate with remote frida-server"

2. **Server running**: `device_shell(command="ps -A | grep frida")`
   - Should show frida-server process
   - If not running: `device_shell(command="su -c '/data/local/tmp/frida-server -D &'")`

3. **Version alignment**: Client and server must match major.minor version
   - Check server: `device_shell(command="/data/local/tmp/frida-server --version")`
   - If mismatch: download matching frida-server from GitHub releases

4. **SELinux (Android)**: Some hooks fail under enforcing mode
   - Check: `device_shell(command="getenforce")`
   - If needed: `device_shell(command="su -c setenforce 0")`

## When to Use Which Frida Mode

| Scenario | Mode | Why |
|----------|------|-----|
| App already running, no anti-debug | `frida_attach` | Simplest, attaches to running process |
| Need hooks before app starts | `frida_spawn` | Spawns app under Frida control, hooks fire early |
| App has anti-Frida detection | See `frida_stealth` skill | Standard modes will crash the app |
| Need to hook iOS system calls | `frida_spawn` + early instrumentation | Attach may miss init-time calls |
| Quick class/method enumeration | `frida_attach` + enumeration script | Lower overhead |

## Common Operations

### Hooking a Method
1. `file_read` the appropriate script from assets, or write inline JS
2. `frida_run_script(package_name="com.target", script=<js_code>)`
3. Check stdout for hook output (messages sent via `send()`)

### SSL Pinning Bypass
1. `frida_run_named_script(package_name="com.target", name="bypass/ssl_pinning_universal")`
2. For a Flutter app, also run `bypass/ssl_pinning_flutter` in its own injection.
3. Read stdout as JSON lines `{ tag, event, data }`. `hook` means a stack was installed, `miss` means that class or export is absent, `hit` means a pin check was neutralized.
4. Confirm traffic in Caido only after a `ready` event.

### Combining Multiple Hooks
Prefer separate `frida_run_named_script` calls. Concatenate sources only when the scripts do not replace the same Java method (`root_detection_universal` and `emulator_detection` both hook `File.exists`). Each bundled script already contains its own message helper.

## Platform Differences

### Android
- frida-server runs as root on device
- Default location: `/data/local/tmp/frida-server`
- Binary name matters for anti-Frida (rename to avoid detection)
- SELinux may block certain hooks

### iOS
- frida-server via Cydia/Sileo on jailbroken device
- Some hooks require entitlement awareness
- Use `frida_spawn` for apps with early jailbreak detection
- `Gadget` mode available for non-jailbroken testing (requires resign)

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "unable to communicate with remote frida-server" | Version mismatch or server not running | Align versions, restart frida-server |
| Hook fires but no output | `send()` not called, or message callback issue | Ensure script uses `send()` for output |
| App crashes on attach | Anti-Frida detection | Switch to `frida_stealth` skill |
| "Failed to spawn: unable to find application" | Wrong package name | Check with `device_shell(command="pm list packages \| grep target")` |
| Hooks not hitting | Class not loaded yet | Use `frida_spawn` for early hooks, or add `Java.scheduleOnMainThread` |
| "Process terminated" | Frida injection detected and killed | Escalate to next stealth tier |
| Timeout with no output | Script error or infinite loop | Check stderr for JS syntax errors |

## Version Notes

- Frida 16.x: stable Java.perform API, improved iOS support
- Frida 15.x -> 16.x: some API changes in spawn behavior
- Always download frida-server matching your `frida --version` from https://github.com/frida/frida/releases