// nsurlsession_hook.js — Observe NSURLSession data-task URLs, methods, and headers. Does not change requests.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/nsurlsession_hook")
// maya-frida-message: { tag, event, data }
//
// Both dataTaskWithRequest: selectors are optional. Bodies are not read.
// Header dictionaries are truncated. A nil request is skipped.
'use strict';

var MAYA = (function () {
  var tag = "nsurlsession_hook";

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

function asObject(pointer) {
  if (!pointer || pointer.isNull()) return null;
  try {
    return ObjC.Object(pointer);
  } catch (error) {
    return null;
  }
}

function hookDataTask(selector) {
  MAYA.guard("NSURLSession " + selector, function () {
    var method = ObjC.classes.NSURLSession && ObjC.classes.NSURLSession[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: selector });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        var request = asObject(args[2]);
        if (!request) return;
        var url = null;
        var methodName = null;
        var headers = null;
        try {
          var nsUrl = request.URL();
          url = nsUrl ? String(nsUrl.absoluteString()) : null;
        } catch (error) {
          url = null;
        }
        try {
          methodName = request.HTTPMethod() ? String(request.HTTPMethod()) : null;
        } catch (error) {
          methodName = null;
        }
        try {
          var fields = request.allHTTPHeaderFields();
          headers = fields && !fields.isNull() ? String(fields) : null;
        } catch (error) {
          headers = null;
        }
        observe({
          hook: selector,
          url: MAYA.text(url, 300),
          method: methodName,
          headers: MAYA.text(headers, 400)
        });
      }
    });
    MAYA.emit("hook", { hook: selector });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else {
  hookDataTask("- dataTaskWithRequest:completionHandler:");
  hookDataTask("- dataTaskWithRequest:");
  MAYA.emit("ready", { script: "nsurlsession_hook", modifies_requests: false });
}
