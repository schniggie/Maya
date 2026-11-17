// wkwebview_load.js — Log WKWebView load URL, scheme, host, MIME type, and HTML or data length. Does not change the load.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/wkwebview_load")
// maya-frida-message: { tag, event, data }
//
// Observation only. Interceptor.attach leaves the original method in place.
// HTML and response bodies are not copied. The script does not navigate.
'use strict';

var MAYA = (function () {
  var tag = "wkwebview_load";

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
    return new ObjC.Object(pointer);
  } catch (error) {
    return null;
  }
}

function lengthOf(pointer) {
  var value = asObject(pointer);
  if (!value || !value.length) return null;
  try {
    return value.length();
  } catch (error) {
    return null;
  }
}

function urlParts(pointer) {
  var url = asObject(pointer);
  if (!url) return { url: null, scheme: null, host: null };
  var absolute = null;
  var scheme = null;
  var host = null;
  try {
    absolute = url.absoluteString ? MAYA.text(url.absoluteString(), 300) : null;
  } catch (error) {
    absolute = null;
  }
  try {
    scheme = url.scheme ? MAYA.text(url.scheme(), 32) : null;
  } catch (error) {
    scheme = null;
  }
  try {
    host = url.host ? MAYA.text(url.host(), 120) : null;
  } catch (error) {
    host = null;
  }
  return { url: absolute, scheme: scheme, host: host };
}

function requestParts(pointer) {
  var request = asObject(pointer);
  if (!request || !request.URL) return { url: null, scheme: null, host: null };
  try {
    return urlParts(request.URL());
  } catch (error) {
    return { url: null, scheme: null, host: null };
  }
}

function hook(selector, onEnter) {
  MAYA.guard("WKWebView " + selector, function () {
    var method = ObjC.classes.WKWebView && ObjC.classes.WKWebView[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: selector });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        var detail = onEnter(args);
        detail.hook = selector;
        detail.modifies_load = false;
        observe(detail);
      }
    });
    MAYA.emit("hook", { hook: selector });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else if (!ObjC.classes.WKWebView) {
  MAYA.emit("miss", { hook: "WKWebView" });
  MAYA.emit("ready", { script: "wkwebview_load", modifies_load: false });
} else {
  hook("- loadRequest:", function (args) {
    return requestParts(args[2]);
  });
  hook("- loadHTMLString:baseURL:", function (args) {
    var base = urlParts(args[3]);
    return { html_length: lengthOf(args[2]), url: base.url, scheme: base.scheme, host: base.host };
  });
  hook("- loadFileURL:allowingReadAccessToURL:", function (args) {
    var file = urlParts(args[2]);
    var access = urlParts(args[3]);
    return { url: file.url, scheme: file.scheme, host: file.host, read_access: access.url };
  });
  hook("- loadData:MIMEType:characterEncodingName:baseURL:", function (args) {
    var base = urlParts(args[5]);
    var mime = null;
    try {
      var mimeValue = asObject(args[3]);
      mime = mimeValue && mimeValue.isKindOfClass_(ObjC.classes.NSString) ? MAYA.text(mimeValue.toString(), 80) : null;
    } catch (error) {
      mime = null;
    }
    return {
      data_length: lengthOf(args[2]),
      mime: mime,
      url: base.url,
      scheme: base.scheme,
      host: base.host
    };
  });
  MAYA.emit("ready", { script: "wkwebview_load", modifies_load: false });
}
