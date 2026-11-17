// integrity_check.js — Report package-signature and digest checks. Does not forge signatures or replace digest output.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/integrity_check")
// maya-frida-message: { tag, event, data }
//
// This is an inspection script. MessageDigest events are capped and contain
// the algorithm and input length only, not the input bytes or digest.
'use strict';

var MAYA = (function () {
  var tag = "integrity_check";

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

var GET_SIGNATURES = 64;
var GET_SIGNING_CERTIFICATES = 0x08000000;
var digestHits = 0;
var DIGEST_CAP = 40;

function flagValue(flags) {
  if (typeof flags === "number") return flags;
  if (flags === null || flags === undefined) return 0;
  try {
    if (typeof flags.intValue === "function") return flags.intValue();
  } catch (error) {
    return 0;
  }
  var parsed = parseInt(flags, 10);
  return isNaN(parsed) ? 0 : parsed;
}

function hookPackageInfo() {
  MAYA.optional("android.app.ApplicationPackageManager.getPackageInfo", function () {
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var packageName = arguments.length ? String(arguments[0]) : "";
        var flags = arguments.length > 1 ? flagValue(arguments[1]) : 0;
        var signatureCheck = (flags & GET_SIGNATURES) !== 0 || (flags & GET_SIGNING_CERTIFICATES) !== 0;
        if (signatureCheck) {
          MAYA.emit("hit", {
            hook: "getPackageInfo",
            package: packageName,
            flags: flags,
            signature_check: true
          });
        }
        return MAYA.callOriginal(overload, this, arguments);
      };
    });
    MAYA.emit("hook", { hook: "ApplicationPackageManager.getPackageInfo" });
  });
}

function hookDigests() {
  MAYA.guard("java.security.MessageDigest.digest", function () {
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = MAYA.callOriginal(overload, this, arguments);
        digestHits += 1;
        if (digestHits <= DIGEST_CAP) {
          var inputLength = 0;
          if (arguments.length && arguments[0] && arguments[0].length !== undefined) inputLength = arguments[0].length;
          var algorithm = "";
          try {
            algorithm = String(this.getAlgorithm());
          } catch (error) {
            algorithm = "";
          }
          MAYA.emit("hit", {
            hook: "MessageDigest.digest",
            algorithm: algorithm,
            input_length: inputLength
          });
        } else if (digestHits === DIGEST_CAP + 1) {
          MAYA.emit("hit", { hook: "MessageDigest.digest", truncated: true, reported: DIGEST_CAP });
        }
        return result;
      };
    });
    MAYA.emit("hook", { hook: "java.security.MessageDigest.digest" });
  });
}

function reportIntegrityClasses() {
  MAYA.guard("integrity class scan", function () {
    var names = Java.enumerateLoadedClassesSync();
    var reported = [];
    names.forEach(function (className) {
      if (reported.length >= 40) return;
      var lowered = className.toLowerCase();
      if (lowered.indexOf("tamper") === -1 && lowered.indexOf("integrity") === -1) return;
      if (className.indexOf("java.") === 0 || className.indexOf("android.") === 0) return;
      var methods = [];
      MAYA.optional(className, function () {
        var cls = Java.use(className);
        var declared = cls.class.getDeclaredMethods();
        var index;
        for (index = 0; index < declared.length && methods.length < 8; index += 1) {
          var methodName = String(declared[index].getName());
          if (methodName.indexOf("check") !== -1 || methodName.indexOf("verify") !== -1) methods.push(methodName);
        }
      });
      reported.push(className);
      MAYA.emit("hit", { hook: "integrity_class", class: className, methods: methods });
    });
    MAYA.emit("done", { hook: "integrity_class", count: reported.length });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookPackageInfo();
      hookDigests();
      reportIntegrityClasses();
      MAYA.emit("ready", { script: "integrity_check", forges_signatures: false });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
