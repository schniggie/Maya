// secure_boot_check.js — Read verified-boot properties, patch level, and whether attestation classes are present. Does not fake attestation.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/secure_boot_check")
// maya-frida-message: { tag, event, data }
//
// Inspection only. Hidden SystemProperties access is attempted and reported
// as "miss" when the platform does not expose it to the app.
'use strict';

var MAYA = (function () {
  var tag = "secure_boot_check";

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

var BOOT_KEYS = [
  "ro.boot.verifiedbootstate",
  "ro.boot.veritymode",
  "ro.boot.flash.locked",
  "ro.boot.vbmeta.device_state",
  "ro.boot.secureboot",
  "ro.secure",
  "ro.debuggable",
  "ro.build.type",
  "ro.build.tags"
];

function readProperties() {
  MAYA.optional("android.os.SystemProperties.get", function () {
    var SystemProperties = Java.use("android.os.SystemProperties");
    var get = SystemProperties.get.overload("java.lang.String", "java.lang.String");
    var values = {};
    BOOT_KEYS.forEach(function (key) {
      try {
        values[key] = String(get.call(SystemProperties, key, "unknown"));
      } catch (error) {
        values[key] = "unreadable";
        MAYA.fail("SystemProperties.get", error);
      }
    });
    var state = values["ro.boot.verifiedbootstate"];
    MAYA.emit("hit", {
      hook: "SystemProperties",
      properties: values,
      verified_boot_green: state === "green",
      release_keys: values["ro.build.tags"] === "release-keys"
    });
  });
}

function readBuild() {
  MAYA.guard("android.os.Build", function () {
    var Build = Java.use("android.os.Build");
    var Version = Java.use("android.os.Build$VERSION");
    MAYA.emit("hit", {
      hook: "Build",
      type: String(Build.TYPE.value),
      tags: String(Build.TAGS.value),
      fingerprint: MAYA.text(Build.FINGERPRINT.value, 180),
      security_patch: Version.SECURITY_PATCH ? String(Version.SECURITY_PATCH.value) : null,
      sdk_int: Version.SDK_INT.value
    });
  });
}

function readKeyStore() {
  MAYA.guard("AndroidKeyStore", function () {
    var KeyStore = Java.use("java.security.KeyStore");
    var keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    MAYA.emit("hit", { hook: "AndroidKeyStore", available: true });
  });
}

function readAttestationClasses() {
  var classes = [
    "com.google.android.gms.safetynet.SafetyNetClient",
    "com.google.android.gms.safetynet.SafetyNetApi",
    "com.google.android.play.core.integrity.IntegrityManager",
    "com.google.android.play.core.integrity.IntegrityManagerFactory"
  ];
  var present = [];
  classes.forEach(function (name) {
    try {
      Java.use(name);
      present.push(name);
      MAYA.emit("hit", { hook: "attestation_class", class: name, present: true });
    } catch (error) {
      MAYA.emit("miss", { hook: "attestation_class", class: name });
    }
  });
  MAYA.emit("done", { hook: "attestation_class", present: present, fakes_attestation: false });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      readBuild();
      readProperties();
      readKeyStore();
      readAttestationClasses();
      MAYA.emit("ready", { script: "secure_boot_check" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
