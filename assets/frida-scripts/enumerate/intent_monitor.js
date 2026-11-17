// intent_monitor.js — Observe activity, broadcast, and service intents the app sends. Does not forge or modify intents.
// category: enumerate
// platform: android
// usage: frida_run_named_script("<package>", "enumerate/intent_monitor")
// maya-frida-message: { tag, event, data }
//
// Each dispatch hook is installed on its own. A missing overload emits "miss".
// Extras are truncated. Hit volume is capped so a chatty app stays readable.
'use strict';

var MAYA = (function () {
  var tag = "intent_monitor";

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

function summarize(intent) {
  var action = null;
  var data = null;
  var component = null;
  var extras = null;
  if (!intent) return { action: null, data: null, component: null, extras: null };
  try {
    action = intent.getAction() ? String(intent.getAction()) : null;
  } catch (error) {
    action = null;
  }
  try {
    data = intent.getDataString() ? String(intent.getDataString()) : null;
  } catch (error) {
    data = null;
  }
  try {
    component = intent.getComponent() ? String(intent.getComponent().flattenToShortString()) : null;
  } catch (error) {
    component = null;
  }
  try {
    extras = intent.getExtras() ? String(intent.getExtras()) : null;
  } catch (error) {
    extras = null;
  }
  return {
    action: action,
    data: MAYA.text(data, 300),
    component: component,
    extras: MAYA.text(extras, 300)
  };
}

function hookOverload(className, methodName, signature, kind) {
  var label = className + "." + methodName;
  MAYA.optional(label + "(" + signature.join(",") + ")", function () {
    var cls = Java.use(className);
    var method = cls[methodName].overload.apply(cls[methodName], signature);
    method.implementation = function () {
      observe({ hook: label, kind: kind, intent: summarize(arguments[0]) });
      return MAYA.callOriginal(method, this, arguments);
    };
    MAYA.emit("hook", { hook: label, signature: signature, kind: kind });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookOverload("android.app.Activity", "startActivity", ["android.content.Intent"], "activity");
      hookOverload("android.app.Activity", "startActivity", ["android.content.Intent", "android.os.Bundle"], "activity");
      hookOverload("android.app.Activity", "startActivityForResult", ["android.content.Intent", "int"], "activity");
      hookOverload("android.content.ContextWrapper", "sendBroadcast", ["android.content.Intent"], "broadcast");
      hookOverload("android.content.ContextWrapper", "startService", ["android.content.Intent"], "service");
      MAYA.emit("ready", { script: "intent_monitor" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
