---
name: ssl_pinning_bypass
description: Universal SSL pinning bypass workflow
category: vulnerabilities
version: "1.2"
last_updated: "2026-11-17"
requires: [frida_operations]
---

# SSL Pinning Bypass Skill

1. Attach or spawn target process with Frida.
2. Inject `bypass/ssl_pinning_universal` with `frida_run_named_script`. It hooks OkHttp3 CertificatePinner, SSLContext TrustManager replacement, Conscrypt trust checks, and WebView SSL errors when those classes exist. For Flutter, run `bypass/ssl_pinning_flutter` separately; it only replaces BoringSSL `SSL_CTX_set_custom_verify` when `libflutter.so` exports it.
3. Parse `{ tag, event, data }` from stdout. Treat `miss` as "this stack is not in the app", not as a failed session.
4. Verify bypass by capturing HTTPS traffic in the proxy, then record which `hook` events fired.

## Tool Quick Reference

- `frida_attach`: attaches to running target process for runtime hooks.
- `frida_spawn`: launches target process under Frida for early hooks.
- `frida_bypass_ssl_pinning`: injects baseline SSL pinning bypass hooks.
- `verify_ssl_bypass`: validates HTTPS interception path after bypass.
- `caido_start`: starts proxy capture engine.
- `caido_set_scope_from_mobile_traffic`: constrains scope to real app API hosts from captured traffic.
- `caido_assess_mobile_api_security`: hands off to API assessment flow once capture is confirmed.

## Handoff Rule

After SSL bypass succeeds and traffic is visible, immediately run API assessment tools on captured mobile API hosts.
Exclude companion app endpoints and local control interfaces from scope.

Severity guidance:
- If bypass succeeds and sensitive data is exposed, report at least High.
- If bypass attempts are blocked by strong controls, record as resilience note.
