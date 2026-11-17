// network_requests.js — Observe OkHttp and URLConnection requests. Reports method and URL only.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/network_requests")
// maya-frida-message: { tag, event, data }
//
// RealCall lives in different packages across OkHttp versions. Each candidate
// is optional. Bodies, headers, and tokens are not recorded.
'use strict';

var MAYA = (function () {
  var tag = "network_requests";

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

function requestFields(request) {
  var method = null;
  var url = null;
  try {
    method = String(request.method());
  } catch (error) {
    method = null;
  }
  try {
    url = String(request.url());
  } catch (error) {
    url = null;
  }
  return { method: method, url: MAYA.text(url, 300) };
}

function hookRealCall(className) {
  MAYA.optional(className, function () {
    var RealCall = Java.use(className);
    if (RealCall.execute) {
      var execute = RealCall.execute.overload();
      execute.implementation = function () {
        var fields = { method: null, url: null };
        try {
          fields = requestFields(this.request());
        } catch (error) {
          MAYA.fail(className + ".request", error);
        }
        observe({ hook: className + ".execute", library: "okhttp", method: fields.method, url: fields.url });
        return execute.call(this);
      };
      MAYA.emit("hook", { hook: className + ".execute" });
    } else {
      MAYA.emit("miss", { hook: className + ".execute" });
    }
    if (RealCall.enqueue && RealCall.enqueue.overloads.length) {
      var enqueue = RealCall.enqueue.overloads[0];
      enqueue.implementation = function () {
        var fields = { method: null, url: null };
        try {
          fields = requestFields(this.request());
        } catch (error) {
          MAYA.fail(className + ".request", error);
        }
        observe({ hook: className + ".enqueue", library: "okhttp", method: fields.method, url: fields.url });
        return MAYA.callOriginal(enqueue, this, arguments);
      };
      MAYA.emit("hook", { hook: className + ".enqueue" });
    }
  });
}

function hookUrlOpen() {
  MAYA.optional("java.net.URL.openConnection", function () {
    var URL = Java.use("java.net.URL");
    var open = URL.openConnection.overload();
    open.implementation = function () {
      observe({ hook: "URL.openConnection", library: "URLConnection", url: MAYA.text(this.toString(), 300) });
      return open.call(this);
    };
    MAYA.emit("hook", { hook: "java.net.URL.openConnection" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookRealCall("okhttp3.internal.connection.RealCall");
      hookRealCall("okhttp3.RealCall");
      hookUrlOpen();
      MAYA.emit("ready", { script: "network_requests" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
