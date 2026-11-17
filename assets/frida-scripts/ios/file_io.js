// file_io.js — Log NSFileManager paths, protection class, and byte length. Does not read file bytes.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/file_io")
// maya-frida-message: { tag, event, data }
//
// Observation only. Interceptor.attach leaves the original method in place.
// createFileAtPath and NSData writes stay in ios/data_protection.
'use strict';

var MAYA = (function () {
  var tag = "file_io";

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

function pathText(pointer) {
  var value = asObject(pointer);
  if (!value) return null;
  try {
    return MAYA.text(value.toString(), 240);
  } catch (error) {
    return null;
  }
}

function protectionOf(pointer) {
  var attrs = asObject(pointer);
  if (!attrs || !attrs.objectForKey_) return null;
  try {
    var value = attrs.objectForKey_("NSFileProtectionKey");
    if (!value || value.isNull()) return "unspecified";
    return MAYA.text(value.toString(), 80);
  } catch (error) {
    return "unreadable";
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

function hook(selector, onEnter) {
  MAYA.guard("NSFileManager " + selector, function () {
    var method = ObjC.classes.NSFileManager && ObjC.classes.NSFileManager[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: selector });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        this.detail = onEnter(args);
      },
      onLeave: function (retval) {
        var detail = this.detail || { hook: selector };
        if (selector === "- contentsAtPath:") detail.length = lengthOf(retval);
        if (selector === "- attributesOfItemAtPath:error:") detail.protection = protectionOf(retval);
        detail.reads_bytes = false;
        observe(detail);
      }
    });
    MAYA.emit("hook", { hook: selector });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else if (!ObjC.classes.NSFileManager) {
  MAYA.emit("miss", { hook: "NSFileManager" });
  MAYA.emit("ready", { script: "file_io", reads_bytes: false });
} else {
  hook("- attributesOfItemAtPath:error:", function (args) {
    return { hook: "- attributesOfItemAtPath:error:", path: pathText(args[2]) };
  });
  hook("- copyItemAtPath:toPath:error:", function (args) {
    return { hook: "- copyItemAtPath:toPath:error:", path: pathText(args[2]), destination: pathText(args[3]) };
  });
  hook("- moveItemAtPath:toPath:error:", function (args) {
    return { hook: "- moveItemAtPath:toPath:error:", path: pathText(args[2]), destination: pathText(args[3]) };
  });
  hook("- removeItemAtPath:error:", function (args) {
    return { hook: "- removeItemAtPath:error:", path: pathText(args[2]) };
  });
  hook("- contentsAtPath:", function (args) {
    return { hook: "- contentsAtPath:", path: pathText(args[2]) };
  });
  hook("- createDirectoryAtPath:withIntermediateDirectories:attributes:error:", function (args) {
    return {
      hook: "- createDirectoryAtPath:withIntermediateDirectories:attributes:error:",
      path: pathText(args[2]),
      protection: protectionOf(args[4])
    };
  });
  MAYA.emit("ready", { script: "file_io", reads_bytes: false });
}
