// class_methods.js — List declared methods and constructors for TARGET_CLASS. Edit that constant before injecting.
// category: enumerate
// platform: android
// usage: frida_run_named_script("<package>", "enumerate/class_methods")
// maya-frida-message: { tag, event, data }
//
// The catalog injects this file as-is. Replace REPLACE_ME with a Java class
// name such as com.example.app.AuthManager. A missing class emits "error".
'use strict';

var TARGET_CLASS = "REPLACE_ME";

var MAYA = (function () {
  var tag = "class_methods";

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

function signaturesOf(items) {
  var found = [];
  var index;
  for (index = 0; index < items.length; index += 1) {
    try {
      found.push(String(items[index].toString()));
    } catch (error) {
      found.push("<unreadable>");
    }
  }
  return found;
}

function emitBatches(kind, items) {
  var batch = [];
  items.forEach(function (signature) {
    batch.push(signature);
    if (batch.length >= 40) {
      MAYA.emit("hit", { class: TARGET_CLASS, kind: kind, signatures: batch.slice() });
      batch = [];
    }
  });
  if (batch.length) MAYA.emit("hit", { class: TARGET_CLASS, kind: kind, signatures: batch });
  return items.length;
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    if (!TARGET_CLASS || TARGET_CLASS === "REPLACE_ME") {
      MAYA.emit("error", {
        hook: "TARGET_CLASS",
        message: "Set TARGET_CLASS to a Java class name before injecting enumerate/class_methods"
      });
      return;
    }
    MAYA.guard(TARGET_CLASS, function () {
      var cls = Java.use(TARGET_CLASS);
      var methods = signaturesOf(cls.class.getDeclaredMethods());
      var constructors = signaturesOf(cls.class.getDeclaredConstructors());
      MAYA.emit("ready", { script: "class_methods", class: TARGET_CLASS });
      var methodCount = emitBatches("method", methods);
      var constructorCount = emitBatches("constructor", constructors);
      MAYA.emit("done", {
        class: TARGET_CLASS,
        methods: methodCount,
        constructors: constructorCount
      });
    });
  });
}
