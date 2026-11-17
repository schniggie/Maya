// pasteboard_monitor.js — Log UIPasteboard reads and writes as change count, UTI, and length. Does not copy contents.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/pasteboard_monitor")
// maya-frida-message: { tag, event, data }
//
// Observation only. Interceptor.attach leaves the original method in place.
// Pasteboard text and data bytes are not put in the message.
'use strict';

var MAYA = (function () {
  var tag = "pasteboard_monitor";

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

function changeCount(pointer) {
  var board = asObject(pointer);
  if (!board || !board.changeCount) return null;
  try {
    return board.changeCount();
  } catch (error) {
    return null;
  }
}

function typeName(pointer) {
  var value = asObject(pointer);
  if (!value) return null;
  try {
    if (value.isKindOfClass_(ObjC.classes.NSString)) return MAYA.text(value.toString(), 80);
  } catch (error) {
    return null;
  }
  return null;
}

function hook(selector, describe) {
  MAYA.guard("UIPasteboard " + selector, function () {
    var method = ObjC.classes.UIPasteboard && ObjC.classes.UIPasteboard[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: selector });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        this.detail = describe(args);
      },
      onLeave: function () {
        observe(this.detail || { hook: selector, copies_contents: false });
      }
    });
    MAYA.emit("hook", { hook: selector });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else if (!ObjC.classes.UIPasteboard) {
  MAYA.emit("miss", { hook: "UIPasteboard" });
  MAYA.emit("ready", { script: "pasteboard_monitor", copies_contents: false });
} else {
  hook("- setString:", function (args) {
    return {
      hook: "- setString:",
      change_count: changeCount(args[0]),
      length: lengthOf(args[2]),
      copies_contents: false
    };
  });
  hook("- string", function (args) {
    return {
      hook: "- string",
      change_count: changeCount(args[0]),
      copies_contents: false
    };
  });
  hook("- setData:forPasteboardType:", function (args) {
    return {
      hook: "- setData:forPasteboardType:",
      change_count: changeCount(args[0]),
      length: lengthOf(args[2]),
      uti: typeName(args[3]),
      copies_contents: false
    };
  });
  hook("- dataForPasteboardType:", function (args) {
    return {
      hook: "- dataForPasteboardType:",
      change_count: changeCount(args[0]),
      uti: typeName(args[2]),
      copies_contents: false
    };
  });
  MAYA.emit("ready", { script: "pasteboard_monitor", copies_contents: false });
}
