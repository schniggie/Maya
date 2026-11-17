// emulator_detection.js — Spoof common emulator signals (Build properties, qemu system properties, telephony ids, emulator device files).
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/emulator_detection")
// maya-frida-message: { tag, event, data }
//
// Telephony values are synthetic lab fixtures, not real identifiers. Sensor
// objects are not fabricated; a fake Sensor instance crashes callers. Do not
// concatenate this script with root_detection_universal: both hook File.exists.
'use strict';

var MAYA = (function () {
  var tag = "emulator_detection";

  function emit(event, data) {
    var message = { tag: tag, event: event, data: data || {} };
    send(message);
    console.log(JSON.stringify(message));
    return message;
  }

  function fail(hook, error) {
    var message = error && error.message ? String(error.message) : String(error);
    return emit("error", { hook: hook, message: message });
  }

  function guard(hook, fn) {
    try {
      return fn();
    } catch (error) {
      fail(hook, error);
      return null;
    }
  }

  function optional(hook, fn) {
    try {
      return fn();
    } catch (error) {
      var message = error && error.message ? String(error.message) : String(error);
      var absent = message.indexOf("ClassNotFound") !== -1
        || message.indexOf("Didn't find class") !== -1
        || message.indexOf("not found") !== -1
        || message.indexOf("has no method") !== -1
        || message.indexOf("undefined") !== -1;
      if (absent) emit("miss", { hook: hook, message: message });
      else fail(hook, error);
      return null;
    }
  }

  function text(value, limit) {
    if (value === null || value === undefined) return null;
    var rendered = String(value);
    var cap = limit || 240;
    if (rendered.length <= cap) return rendered;
    return rendered.slice(0, cap) + "...";
  }

  function callOriginal(method, receiver, args) {
    var count = args.length;
    if (count === 0) return method.call(receiver);
    if (count === 1) return method.call(receiver, args[0]);
    if (count === 2) return method.call(receiver, args[0], args[1]);
    if (count === 3) return method.call(receiver, args[0], args[1], args[2]);
    if (count === 4) return method.call(receiver, args[0], args[1], args[2], args[3]);
    if (count === 5) return method.call(receiver, args[0], args[1], args[2], args[3], args[4]);
    if (count === 6) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5]);
    if (count === 7) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
    if (count === 8) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
    fail("callOriginal", "unsupported arity " + count);
    return null;
  }

  return {
    emit: emit,
    fail: fail,
    guard: guard,
    optional: optional,
    text: text,
    callOriginal: callOriginal
  };
})();

var EMULATOR_FILES = {
  "/dev/qemu_pipe": true,
  "/dev/socket/qemud": true,
  "/dev/goldfish_pipe": true,
  "/dev/socket/genyd": true,
  "/system/lib/libc_malloc_debug_qemu.so": true,
  "/sys/qemu_trace": true,
  "/system/bin/qemu-props": true,
  "/system/bin/nox-prop": true
};

var PROPERTY_OVERRIDES = {
  "ro.kernel.qemu": "0",
  "ro.boot.qemu": "0",
  "ro.kernel.android.qemud": "",
  "ro.hardware": "oriole",
  "ro.hardware.chipname": "oriole",
  "ro.product.model": "Pixel 6",
  "ro.product.manufacturer": "Google",
  "ro.product.brand": "google",
  "ro.product.device": "oriole",
  "ro.product.name": "oriole",
  "ro.boot.hardware": "oriole",
  "init.svc.qemud": "",
  "init.svc.qemu-props": ""
};

function isEmulatorFile(path) {
  if (!path) return false;
  if (Object.prototype.hasOwnProperty.call(EMULATOR_FILES, path)) return true;
  if (path.indexOf("goldfish") !== -1) return true;
  if (path.indexOf("/qemu") !== -1 || path.indexOf("qemu_") !== -1) return true;
  if (path.indexOf("genymotion") !== -1) return true;
  return false;
}

function hookBuild() {
  MAYA.guard("android.os.Build", function () {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/oriole/oriole:12/SP1A.210812.016.C1/7955498:user/release-keys";
    Build.MODEL.value = "Pixel 6";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "oriole";
    Build.PRODUCT.value = "oriole";
    Build.HARDWARE.value = "oriole";
    Build.BOARD.value = "oriole";
    Build.TAGS.value = "release-keys";
    MAYA.emit("hook", { hook: "android.os.Build", model: "Pixel 6" });
  });
}

function hookSystemProperties() {
  MAYA.optional("android.os.SystemProperties.get", function () {
    var SystemProperties = Java.use("android.os.SystemProperties");
    var getOne = SystemProperties.get.overload("java.lang.String");
    var getTwo = SystemProperties.get.overload("java.lang.String", "java.lang.String");
    function override(key) {
      var name = String(key);
      if (!Object.prototype.hasOwnProperty.call(PROPERTY_OVERRIDES, name)) return null;
      MAYA.emit("hit", { hook: "SystemProperties.get", key: name });
      return PROPERTY_OVERRIDES[name];
    }
    getOne.implementation = function (key) {
      var value = override(key);
      if (value !== null) return value;
      return getOne.call(this, key);
    };
    getTwo.implementation = function (key, fallback) {
      var value = override(key);
      if (value !== null) return value;
      return getTwo.call(this, key, fallback);
    };
    MAYA.emit("hook", { hook: "android.os.SystemProperties.get" });
  });
}

function hookTelephonyMethod(telephony, name, value) {
  MAYA.optional("android.telephony.TelephonyManager." + name, function () {
    if (!telephony[name]) {
      MAYA.emit("miss", { hook: "TelephonyManager." + name });
      return;
    }
    telephony[name].overloads.forEach(function (overload) {
      overload.implementation = function () {
        MAYA.emit("hit", { hook: "TelephonyManager." + name });
        return value;
      };
    });
    MAYA.emit("hook", { hook: "TelephonyManager." + name });
  });
}

function hookTelephony() {
  MAYA.optional("android.telephony.TelephonyManager", function () {
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    hookTelephonyMethod(TelephonyManager, "getDeviceId", "000000000000000");
    hookTelephonyMethod(TelephonyManager, "getImei", "000000000000000");
    hookTelephonyMethod(TelephonyManager, "getMeid", "00000000000000");
    hookTelephonyMethod(TelephonyManager, "getSubscriberId", "000000000000000");
    hookTelephonyMethod(TelephonyManager, "getLine1Number", "0000000000");
    hookTelephonyMethod(TelephonyManager, "getNetworkOperatorName", "LabCarrier");
    hookTelephonyMethod(TelephonyManager, "getSimOperatorName", "LabCarrier");
  });
}

function hookEmulatorFiles() {
  MAYA.guard("java.io.File.exists", function () {
    var File = Java.use("java.io.File");
    var exists = File.exists;
    exists.implementation = function () {
      var path = "";
      try {
        path = String(this.getAbsolutePath());
      } catch (error) {
        return exists.call(this);
      }
      if (isEmulatorFile(path)) {
        MAYA.emit("hit", { hook: "java.io.File.exists", path: path });
        return false;
      }
      return exists.call(this);
    };
    MAYA.emit("hook", { hook: "java.io.File.exists" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookBuild();
      hookSystemProperties();
      hookTelephony();
      hookEmulatorFiles();
      MAYA.emit("ready", { script: "emulator_detection" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
