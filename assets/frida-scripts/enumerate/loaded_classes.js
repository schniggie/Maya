// loaded_classes.js — Enumerate loaded Java classes in batches, optionally filtered by the FILTER substring.
// category: enumerate
// platform: android
// usage: frida_run_named_script("<package>", "enumerate/loaded_classes")
// maya-frida-message: { tag, event, data }
//
// Edit FILTER before injecting. An empty FILTER lists every loaded class.
// Names are sent in batches so a large app does not flood the session.
'use strict';

var FILTER = "";
var BATCH = 100;

var MAYA = (function () {
  var tag = "loaded_classes";

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

function enumerateLoadedClasses() {
  var names = Java.enumerateLoadedClassesSync();
  var batch = [];
  var total = 0;
  names.forEach(function (className) {
    if (FILTER && className.indexOf(FILTER) === -1) return;
    total += 1;
    batch.push(className);
    if (batch.length >= BATCH) {
      MAYA.emit("hit", { classes: batch.slice(), count: batch.length });
      batch = [];
    }
  });
  if (batch.length) MAYA.emit("hit", { classes: batch, count: batch.length });
  MAYA.emit("done", { total: total, filter: FILTER, scanned: names.length });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      MAYA.emit("ready", { script: "loaded_classes", filter: FILTER });
      enumerateLoadedClasses();
    } catch (error) {
      MAYA.fail("enumerateLoadedClasses", error);
    }
  });
}
