// shared_preferences.js — Observe SharedPreferences reads and writes. Values are truncated and stay in the local Frida session.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/shared_preferences")
// maya-frida-message: { tag, event, data }
//
// EditorImpl is optional because some platform builds rename the editor class.
// Each getter is hooked on its own so one missing method does not drop the rest.
'use strict';

var MAYA = (function () {
  var tag = "shared_preferences";

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

var hits = 0;
var HIT_CAP = 80;

function observe(data) {
  hits += 1;
  if (hits <= HIT_CAP) {
    MAYA.emit("hit", data);
    return;
  }
  if (hits === HIT_CAP + 1) MAYA.emit("hit", { truncated: true, reported: HIT_CAP });
}

function hookGetterSimple(className, name) {
  MAYA.optional(className + "." + name, function () {
    var cls = Java.use(className);
    if (!cls[name] || !cls[name].overloads.length) {
      MAYA.emit("miss", { hook: className + "." + name });
      return;
    }
    var method = cls[name].overloads[0];
    method.implementation = function (key, defValue) {
      var value = method.call(this, key, defValue);
      observe({
        hook: className + "." + name,
        op: "read",
        key: MAYA.text(key, 120),
        value: MAYA.text(value, 180)
      });
      return value;
    };
    MAYA.emit("hook", { hook: className + "." + name });
  });
}

function hookEditor(className, name) {
  MAYA.optional(className + "." + name, function () {
    var cls = Java.use(className);
    if (!cls[name]) {
      MAYA.emit("miss", { hook: className + "." + name });
      return;
    }
    var method = cls[name].overloads[0];
    method.implementation = function (key, value) {
      observe({
        hook: className + "." + name,
        op: "write",
        key: MAYA.text(key, 120),
        value: MAYA.text(value, 180)
      });
      return method.call(this, key, value);
    };
    MAYA.emit("hook", { hook: className + "." + name });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      ["getString", "getStringSet", "getInt", "getLong", "getFloat", "getBoolean"].forEach(function (name) {
        hookGetterSimple("android.app.SharedPreferencesImpl", name);
      });
      ["putString", "putStringSet", "putInt", "putLong", "putFloat", "putBoolean"].forEach(function (name) {
        hookEditor("android.app.SharedPreferencesImpl$EditorImpl", name);
      });
      MAYA.emit("ready", { script: "shared_preferences" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
