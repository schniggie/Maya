// data_protection.js — Report iOS file-protection classes used when the app creates or writes files.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/data_protection")
// maya-frida-message: { tag, event, data }
//
// ObjC.available is required. Missing selectors emit "miss". File bytes are
// not read. NSData write options are mapped to the NSFileProtection class.
'use strict';

var MAYA = (function () {
  var tag = "data_protection";

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

var PROTECTION_MASK = 0xf0000000;
var PROTECTION_CLASSES = {};
PROTECTION_CLASSES[0x10000000] = "NSFileProtectionNone";
PROTECTION_CLASSES[0x20000000] = "NSFileProtectionComplete";
PROTECTION_CLASSES[0x30000000] = "NSFileProtectionCompleteUnlessOpen";
PROTECTION_CLASSES[0x40000000] = "NSFileProtectionCompleteUntilFirstUserAuthentication";

function asObject(pointer) {
  if (!pointer || pointer.isNull()) return null;
  try {
    return ObjC.Object(pointer);
  } catch (error) {
    return null;
  }
}

function protectionFromOptions(options) {
  var masked = options & PROTECTION_MASK;
  return PROTECTION_CLASSES[masked] || (masked === 0 ? "unspecified" : "options_" + masked.toString(16));
}

function hookCreateFile() {
  var selector = "- createFileAtPath:contents:attributes:";
  MAYA.guard("NSFileManager " + selector, function () {
    var method = ObjC.classes.NSFileManager && ObjC.classes.NSFileManager[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: "NSFileManager.createFileAtPath" });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        var path = asObject(args[2]);
        var attrs = asObject(args[4]);
        var protection = "none";
        if (attrs) {
          try {
            var value = attrs.objectForKey_("NSFileProtectionKey");
            if (value && !value.isNull()) protection = String(value);
          } catch (error) {
            protection = "unreadable";
          }
        }
        MAYA.emit("hit", {
          hook: "NSFileManager.createFileAtPath",
          path: MAYA.text(path ? path.toString() : null, 240),
          protection: protection
        });
      }
    });
    MAYA.emit("hook", { hook: "NSFileManager.createFileAtPath" });
  });
}

function hookDataWrite() {
  var selector = "- writeToFile:options:error:";
  MAYA.guard("NSData " + selector, function () {
    var method = ObjC.classes.NSData && ObjC.classes.NSData[selector];
    if (!method || !method.implementation) {
      MAYA.emit("miss", { hook: "NSData.writeToFile" });
      return;
    }
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        var path = asObject(args[2]);
        var options = 0;
        try {
          options = args[3].toUInt32();
        } catch (error) {
          options = 0;
        }
        MAYA.emit("hit", {
          hook: "NSData.writeToFile",
          path: MAYA.text(path ? path.toString() : null, 240),
          protection: protectionFromOptions(options)
        });
      }
    });
    MAYA.emit("hook", { hook: "NSData.writeToFile" });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else {
  hookCreateFile();
  hookDataWrite();
  MAYA.emit("ready", { script: "data_protection" });
}
