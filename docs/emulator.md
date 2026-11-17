# Headless Android emulator

Maya's dynamic path can run against a headless Android Virtual Device. No phone is required. This is orchestration around the existing Frida catalog and companion client: boot an AVD, install an APK, start `frida-server`, and inject one `enumerate/` script.

`--emulator` does not start an LLM and does not overlap with `--static-only`. Run one of those at a time.

The bundled lab APK is Damn Vulnerable Bank:

```text
dvba_v1.1.0.apk
package: com.app.damnvulnerablebank
```

## Prerequisites

| Piece | Why |
| --- | --- |
| Android SDK command-line tools | `sdkmanager`, `avdmanager` |
| `emulator` and `platform-tools` (`adb`) | boot and install |
| A **google_apis** or **aosp_atd** system image | userdebug, so `adb root` works |
| JDK 17 | the SDK command-line tools |
| KVM (Linux) or Hypervisor.framework (macOS) | the emulator refuses to boot x86_64 without it |
| `pip install -e ".[dynamic]"` | pins `frida==16.7.19` and `frida-tools==13.6.1` |

`ANDROID_HOME` or `ANDROID_SDK_ROOT` should point at the SDK root. The helper also checks `~/Android/Sdk`, `~/Library/Android/sdk`, and `emulator` / `adb` / `avdmanager` on `PATH`.

Install a default image (API 34, x86_64, google_apis):

```bash
sdkmanager --install \
  "cmdline-tools;latest" \
  "platform-tools" \
  "emulator" \
  "platforms;android-34" \
  "system-images;android-34;google_apis;x86_64"
```

Play Store images (`google_apis_playstore`) are production builds. `adb root` fails there, and the helper stops with `missing: root` instead of pushing `frida-server`.

A missing SDK, emulator binary, or `adb` prints the reason and exits 2. It does not raise a traceback.

## Boot only

`scripts/emulator_up.sh` creates the AVD if needed, starts it headless, and waits for `sys.boot_completed`. It leaves the emulator running.

```bash
scripts/emulator_up.sh up
scripts/emulator_up.sh status
scripts/emulator_up.sh down
```

The same flags exist as environment variables:

| Flag | Environment | Default |
| --- | --- | --- |
| `--api` | `MAYA_AVD_API` | `34` |
| `--abi` | `MAYA_AVD_ABI` | host: `x86_64` on x86_64, `arm64-v8a` on Apple Silicon / aarch64 |
| `--device` | `MAYA_AVD_DEVICE` | `pixel_6` |
| `--name` | `MAYA_AVD_NAME` | `maya` |
| `--port` | `MAYA_AVD_PORT` | `5554` (even console port; adb serial is `emulator-5554`) |
| `--image-tag` | `MAYA_AVD_IMAGE_TAG` | `google_apis` |
| `--boot-timeout` | `MAYA_EMULATOR_BOOT_TIMEOUT` | `360` seconds |

The process is started with `-no-window -no-audio -gpu swiftshader_indirect -no-boot-anim`. SwiftShader is software GLES. It does not replace CPU virtualization.

`down` stops only `emulator-<port>`. Other adb devices are left alone.

## Dynamic smoke

```bash
pip install -e ".[dev,dynamic]"
maya --emulator --package dvba_v1.1.0.apk
```

What that does:

1. Boot the AVD, or reuse `emulator-5554` if it is already booted. An emulator this command started is torn down at the end. One it reused is left running. `--keep-emulator` leaves either one running.
2. `adb install -r` the APK. The package name comes from `--target` when that looks like a package, otherwise from the APK manifest.
3. Download `frida-server` for the emulator ABI, push it to `/data/local/tmp/frida-server`, and health-check it. The version is `--frida-version`, then `MAYA_FRIDA_VERSION`, then the installed `frida` distribution, then the pin `16.7.19`. The download URL is only `https://github.com/frida/frida/releases/download/<version>/frida-server-<version>-android-<arch>.xz`.
4. `frida_list_scripts` and `frida_load_script` must resolve the smoke script from the catalog.
5. Forward `tcp:9999` and call the companion client's `GET /health`. A missing companion is reported and does not fail the smoke. Damn Vulnerable Bank is not the companion app.
6. Launch the app and inject the smoke script through `frida_run_named_script`. The default is `enumerate/loaded_classes`. `enumerate/class_methods` is the other usual choice. Names outside `enumerate/` are rejected before the emulator starts.
7. Write `emulator-smoke.json` under `--output-dir` (default `maya_runs/<package>/`).

```bash
maya --emulator --package dvba_v1.1.0.apk --avd-api 34 --avd-abi x86_64
maya --emulator --package app.apk --smoke-script enumerate/class_methods --keep-emulator
```

Shipped enumerate scripts use Frida 16's `Java.perform` bridge. The `dynamic` extra pins Frida 16.7.19 so the client and `frida-server` match. Frida 17 removed that embedded bridge; stay on 16.x with these scripts.

`MAYA_EMULATOR_SMOKE_TIMEOUT` (default 25 seconds) is how long the attach may run. Enumeration scripts keep the session open, so a timeout after the script printed output is a pass.

## Linux and KVM

x86_64 images need `/dev/kvm` that your user can open. Nested virtualization has to be enabled on a VM (`kvm-ok`, or `egrep -c '(vmx|svm)' /proc/cpuinfo`). If the emulator exits immediately, the helper returns the emulator log instead of hanging. The usual line is that hardware acceleration is missing.

```bash
sudo usermod -aG kvm "$USER"   # then start a new login
ls -l /dev/kvm
```

On GitHub-hosted Linux runners, `/dev/kvm` exists for Android emulation but is not writable until a udev rule opens it. The optional workflow below does that. See [GitHub's Android virtualization note](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/).

## Apple Silicon

`platform.machine()` is `arm64`, so the default ABI is `arm64-v8a`. Install `system-images;android-34;google_apis;arm64-v8a`. An x86_64 system image does not run on the Apple Silicon hypervisor.

macOS uses Hypervisor.framework, not `/dev/kvm`. `-no-window -no-audio -gpu swiftshader_indirect` still applies. `ANDROID_HOME` is usually `~/Library/Android/sdk` after Android Studio or `brew install --cask android-commandlinetools`.

The `frida-server` asset for that image is `android-arm64`, not the macOS Frida binary.

## CI

[`.github/workflows/emulator-dynamic.yml`](../.github/workflows/emulator-dynamic.yml) runs on `workflow_dispatch` and a weekly schedule. It is **not** called from `ci.yml` and must not be a required status check. Pull requests stay on the device-free suite (ruff, pytest without `integration` or `smoke`, the DVBA static smoke, the reusable static scan, and the docker build).

The job enables KVM, installs the API 34 google_apis x86_64 image, and runs:

```bash
maya --emulator --package dvba_v1.1.0.apk --avd-abi x86_64
```

If `/dev/kvm` is still missing, the job skips with a notice instead of failing. That keeps a hosted runner without KVM from turning an optional weekly job red. A real smoke failure (SDK, boot, or Frida) still fails the job, and that failure does not block merges.

The local path when a runner cannot boot an emulator:

```bash
scripts/emulator_up.sh up
maya --emulator --package dvba_v1.1.0.apk
```

Unit tests in `tests/test_emulator.py` and `tests/test_headless_dynamic.py` cover ABI selection, version resolution, a missing SDK, and the enumerate-only smoke. They do not boot an emulator. A live boot is marked `integration` and skips unless `MAYA_EMULATOR_INTEGRATION=1`.
