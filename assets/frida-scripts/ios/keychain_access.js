// keychain_access.js — Log SecItem class, service, account, access group, accessibility, and status. Does not copy passwords or key bytes.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/keychain_access")
// maya-frida-message: { tag, event, data }
//
// Observation only. Interceptor.attach leaves the original function in place.
// NSData and other non-string attributes are skipped.
'use strict';

var MAYA = (function () {
  var tag = "keychain_access";

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
var CONSTANTS = {};
var EXPORTS = ["SecItemCopyMatching", "SecItemAdd", "SecItemUpdate", "SecItemDelete"];
var ATTRS = [
  ["sec_class", "kSecClass"],
  ["service", "kSecAttrService"],
  ["account", "kSecAttrAccount"],
  ["access_group", "kSecAttrAccessGroup"],
  ["accessible", "kSecAttrAccessible"]
];

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

function constant(name) {
  if (Object.prototype.hasOwnProperty.call(CONSTANTS, name)) return CONSTANTS[name];
  var found = null;
  try {
    var exp = Module.findExportByName("Security", name);
    if (!exp) exp = Module.findExportByName(null, name);
    if (exp && !exp.isNull()) found = new ObjC.Object(exp.readPointer());
  } catch (error) {
    found = null;
  }
  CONSTANTS[name] = found;
  return found;
}

function asText(value) {
  if (!value || value.isNull()) return null;
  try {
    if (value.isKindOfClass_(ObjC.classes.NSString)) return MAYA.text(value.toString(), 80);
    if (value.isKindOfClass_(ObjC.classes.NSNumber)) return MAYA.text(value.stringValue(), 40);
  } catch (error) {
    return null;
  }
  return null;
}

function readQuery(pointer) {
  var meta = {
    sec_class: null,
    service: null,
    account: null,
    access_group: null,
    accessible: null
  };
  var query = asObject(pointer);
  if (!query || !query.objectForKey_) return meta;
  ATTRS.forEach(function (pair) {
    var key = constant(pair[1]);
    if (!key) return;
    try {
      meta[pair[0]] = asText(query.objectForKey_(key));
    } catch (error) {
      meta[pair[0]] = null;
    }
  });
  return meta;
}

function hookExport(name) {
  MAYA.optional(name, function () {
    var address = Module.findExportByName("Security", name);
    if (!address) address = Module.findExportByName(null, name);
    if (!address) {
      MAYA.emit("miss", { hook: name });
      return;
    }
    Interceptor.attach(address, {
      onEnter: function (args) {
        this.meta = readQuery(args[0]);
      },
      onLeave: function (retval) {
        var meta = this.meta || {};
        observe({
          hook: name,
          status: retval.toInt32(),
          sec_class: meta.sec_class || null,
          service: meta.service || null,
          account: meta.account || null,
          access_group: meta.access_group || null,
          accessible: meta.accessible || null,
          copies_secrets: false
        });
      }
    });
    MAYA.emit("hook", { hook: name });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else {
  EXPORTS.forEach(hookExport);
  MAYA.emit("ready", { script: "keychain_access", copies_secrets: false });
}
